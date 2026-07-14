"""Orchestrate GitHub sources -> enumerate repos -> clone -> scan -> push.

Mirrors the image-scanner pipeline: discover targets, scan each (optionally
concurrently), then publish to the platform unless dry-run/no-push.
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from github_inventory.config import Config as ScanConfig
from github_inventory.engine import ScanEngine
from github_inventory.repo_loader import resolve_repo

from .config import Config
from .connector import GithubConnector, RepoTarget
from .github_api import GithubApiError
from .mapper import build_discovery_payload, build_payload
from .publisher import push_repo
from .sbom import extract_repo_sbom

log = logging.getLogger("gbom_sync.pipeline")


@dataclass
class RepoResult:
    repo: RepoTarget
    payload: dict[str, Any] | None = None
    component_count: int = 0
    finding_count: int = 0
    error: str = ""
    pushed: bool = False
    push_error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class PipelineResult:
    discovered: list[RepoTarget] = field(default_factory=list)
    results: list[RepoResult] = field(default_factory=list)
    pushed: int = 0
    errors: list[str] = field(default_factory=list)
    per_source: dict[str, int] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        ok = [r for r in self.results if r.ok]
        return {
            "discovered": len(self.discovered),
            "scanned_ok": len(ok),
            "scanned_failed": len([r for r in self.results if not r.ok]),
            "pushed": self.pushed,
            "by_source": self.per_source,
            "total_components": sum(r.component_count for r in ok),
            "total_findings": sum(r.finding_count for r in ok),
            "errors": self.errors,
        }


def discover(config: Config, sources_filter: set[str] | None = None) -> tuple[
    list[tuple[str, RepoTarget]], list[str], dict[str, int]
]:
    pairs: list[tuple[str, RepoTarget]] = []
    errors: list[str] = []
    per_source: dict[str, int] = {}
    enabled = [
        s for s in config.sources if s.enabled and (not sources_filter or s.name in sources_filter)
    ]
    log.info("discovering from %d source(s): %s", len(enabled), ", ".join(s.name for s in enabled) or "(none)")
    for source in enabled:
        log.info("[%s] listing repositories…", source.name)
        t0 = time.monotonic()
        try:
            connector = GithubConnector(source)
            count = 0
            for repo in connector.discover_repos():
                pairs.append((source.name, repo))
                count += 1
            per_source[source.name] = count
            log.info("[%s] discovered %d repo(s) in %.1fs", source.name, count, time.monotonic() - t0)
        except (GithubApiError, RuntimeError) as exc:
            log.error("[%s] discovery failed: %s", source.name, exc)
            errors.append(f"[{source.name}] {exc}")
    log.info("discovery complete: %d repo(s) to scan", len(pairs))
    return pairs, errors, per_source


def run(
    config: Config,
    sources_filter: set[str] | None = None,
    dry_run: bool = False,
    push: bool | None = None,
    inventory_only: bool = False,
) -> PipelineResult:
    t_start = time.monotonic()
    result = PipelineResult()
    pairs, errors, per_source = discover(config, sources_filter)
    result.errors.extend(errors)
    result.per_source = per_source
    result.discovered = [repo for _, repo in pairs]

    if dry_run:
        log.info("dry-run: discovery only, not cloning/scanning")
        return result

    total = len(pairs)
    workers = max(1, int(config.scanner.concurrency))
    should_push = config.platform.push if push is None else push

    if inventory_only:
        for source_name, repo in pairs:
            payload = build_discovery_payload(repo, source_name)
            if not should_push:
                continue
            try:
                push_repo(config.platform.url, payload)
                result.pushed += 1
            except RuntimeError as exc:
                result.errors.append(f"[{repo.full_name}] inventory push: {exc}")
                log.error("inventory push failed %s — %s", repo.full_name, exc)
        log.info(
            "inventory refresh complete: discovered=%d pushed=%d errors=%d",
            len(result.discovered), result.pushed, len(result.errors),
        )
        return result

    log.info("scanning %d repo(s) (concurrency=%d, push=%s)…", total, workers, should_push)
    done = 0
    lock = threading.Lock()
    scan_cfg = ScanConfig()  # default scanner config (AI off)

    def scan_one(source_name: str, repo: RepoTarget) -> RepoResult:
        nonlocal done
        t0 = time.monotonic()
        try:
            with resolve_repo(repo.clone_url, token=repo.token, timeout=config.scanner.clone_timeout) as root:
                scan_result = ScanEngine(Path(root), scan_cfg).run()
                # Optional declared-dependency SBOM (syft) + CVEs (grype) on the clone.
                cyclonedx = None
                if config.scanner.scan_sbom:
                    cyclonedx = extract_repo_sbom(
                        str(root),
                        syft_bin=config.scanner.syft_bin,
                        grype_bin=config.scanner.grype_bin,
                        scan_vulnerabilities=config.scanner.scan_vulnerabilities,
                        timeout=config.scanner.scan_timeout,
                    )
            payload = build_payload(repo, scan_result, source_name, cyclonedx=cyclonedx)
            res = RepoResult(
                repo=repo,
                payload=payload,
                component_count=payload["scan_metadata"]["component_count"],
                finding_count=payload["scan_metadata"]["finding_count"],
            )
        except (RuntimeError, ValueError, OSError) as exc:
            res = RepoResult(repo=repo, error=str(exc))

        # Push immediately, per repo, so partial progress survives a crash/kill and
        # memory stays bounded (the payload is released once it's persisted).
        if res.ok and should_push:
            try:
                push_repo(config.platform.url, res.payload)
                res.pushed = True
                res.payload = None
            except RuntimeError as exc:
                res.push_error = str(exc)

        dt = time.monotonic() - t0
        with lock:
            done += 1
            if res.pushed:
                result.pushed += 1
            n = done
        if not res.ok:
            log.warning("✗ [%d/%d] %s — %s", n, total, repo.full_name, res.error)
        else:
            tail = "" if not should_push else (" · pushed" if res.pushed else " · PUSH FAILED")
            log.info("✓ [%d/%d] %s → %d dep(s), %d finding(s) (%.1fs)%s",
                     n, total, repo.full_name, res.component_count, res.finding_count, dt, tail)
        return res

    if workers == 1 or total <= 1:
        results = [scan_one(name, repo) for name, repo in pairs]
    else:
        results = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(scan_one, name, repo) for name, repo in pairs]
            for fut in as_completed(futures):
                results.append(fut.result())
    result.results = results
    for res in results:
        if not res.ok:
            result.errors.append(f"[{res.repo.full_name}] scan failed: {res.error}")
        elif res.push_error:
            result.errors.append(f"[{res.repo.full_name}] push: {res.push_error}")

    ok_n = len([r for r in results if r.ok])
    if should_push:
        log.info("pushed %d/%d repo SBOM(s) to %s", result.pushed, ok_n, config.platform.url)
    elif ok_n:
        log.info("push disabled (--no-push): built %d payload(s)", ok_n)

    s = result.summary()
    log.info(
        "done in %.1fs · discovered=%d scanned_ok=%d failed=%d pushed=%d components=%d findings=%d errors=%d",
        time.monotonic() - t_start, s["discovered"], s["scanned_ok"], s["scanned_failed"],
        s["pushed"], s["total_components"], s["total_findings"], len(result.errors),
    )
    return result


# --------------------------------------------------------------------------- #
# Local CLI mode: scan a repo path or URL directly (no platform, no config).
# --------------------------------------------------------------------------- #
def local_repo_target(target: str) -> RepoTarget:
    """Build a RepoTarget from a local directory path or a github URL/slug."""
    from .connector import _SLUG_RE

    path = Path(target).expanduser()
    if path.exists() and path.is_dir():
        name = path.resolve().name
        return RepoTarget(
            full_name=f"local/{name}", owner="local", repo=name,
            clone_url=str(path.resolve()), html_url=str(path.resolve()),
            visibility="local", discovered_via={"local": True},
        )
    match = _SLUG_RE.match(target.strip())
    if match:
        full = f"{match.group(1)}/{match.group(2)}"
        owner, _, repo = full.partition("/")
        return RepoTarget(
            full_name=full, owner=owner, repo=repo,
            clone_url=f"https://github.com/{full}.git", html_url=f"https://github.com/{full}",
            visibility="public", discovered_via={"local": True},
        )
    raise ValueError(f"'{target}' is not a local repo directory or a github URL/owner-repo slug")


def run_local(targets: list[str], scanner_cfg) -> PipelineResult:
    """Scan repo path(s)/URL(s) with phantom-deps + syft + grype — no push."""
    result = PipelineResult()
    scan_cfg = ScanConfig()
    total = len(targets)
    for i, target in enumerate(targets, 1):
        repo = None
        try:
            repo = local_repo_target(target)
            result.discovered.append(repo)
            t0 = time.monotonic()
            with resolve_repo(repo.clone_url, token=repo.token, timeout=scanner_cfg.clone_timeout) as root:
                scan_result = ScanEngine(Path(root), scan_cfg).run()
                cyclonedx = None
                if scanner_cfg.scan_sbom:
                    cyclonedx = extract_repo_sbom(
                        str(root), syft_bin=scanner_cfg.syft_bin, grype_bin=scanner_cfg.grype_bin,
                        scan_vulnerabilities=scanner_cfg.scan_vulnerabilities, timeout=scanner_cfg.scan_timeout,
                    )
            payload = build_payload(repo, scan_result, "local", cyclonedx=cyclonedx)
            res = RepoResult(repo=repo, payload=payload,
                             component_count=payload["scan_metadata"]["component_count"],
                             finding_count=payload["scan_metadata"]["finding_count"])
            result.results.append(res)
            log.info("✓ [%d/%d] %s → %d dep(s), %d finding(s) (%.1fs)",
                     i, total, repo.full_name, res.component_count, res.finding_count, time.monotonic() - t0)
        except (RuntimeError, ValueError, OSError) as exc:
            result.results.append(RepoResult(repo=repo, error=str(exc)))
            result.errors.append(f"[{target}] {exc}")
            log.warning("✗ [%d/%d] %s — %s", i, total, target, exc)
    return result


def flatten_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Human-friendly per-repo view: components + CVE vulnerabilities + phantom-dep issues."""
    asset = (payload.get("assets") or [{}])[0]
    comps = payload.get("components") or []
    by_key: dict[str, dict[str, Any]] = {}
    for comp in comps:
        if comp.get("ref"):
            by_key[comp["ref"]] = comp
        purl = comp.get("purl") or ""
        if purl:
            by_key.setdefault(purl.split("?")[0], comp)
    vulns, issues, malware = [], [], []
    for finding in payload.get("findings") or []:
        ftype = finding.get("finding_type")
        if ftype == "cve":
            ref = finding.get("component_ref") or ""
            comp = by_key.get(ref) or by_key.get(ref.split("?")[0]) or {}
            vulns.append({
                "id": finding.get("title", ""), "severity": finding.get("severity", ""),
                "package": comp.get("name", ""), "version": comp.get("version", ""),
                "fix": finding.get("fix_recommendation", ""),
            })
        elif ftype == "malware":
            ev = finding.get("evidence") or {}
            malware.append({
                "advisory_id": finding.get("title", ""), "package": ev.get("package", ""),
                "version": ev.get("version", ""), "advisory_url": ev.get("advisory_url", ""),
            })
        else:
            ev = finding.get("evidence") or {}
            issues.append({
                "type": finding.get("finding_type", ""), "severity": finding.get("severity", ""),
                "title": finding.get("title", ""), "file": ev.get("file", ""), "line": ev.get("line", ""),
            })
    return {
        "target": asset.get("external_id") or asset.get("display_name") or "",
        "asset_type": asset.get("asset_type", ""),
        "summary": {"components": len(comps), "vulnerabilities": len(vulns),
                    "issues": len(issues), "malware": len(malware)},
        "components": [
            {"name": c.get("name", ""), "version": c.get("version", ""), "ecosystem": c.get("ecosystem", ""),
             "package_manager": c.get("package_manager", ""), "purl": c.get("purl", ""), "license": c.get("license", "")}
            for c in comps
        ],
        "vulnerabilities": vulns,
        "issues": issues,
        "malware": malware,
    }
