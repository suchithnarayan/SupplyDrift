"""Orchestrate sources -> connectors -> core scan -> wrap -> publish.

Flow:

1. Build a :class:`RegistryAuthIndex` from the configured registries so services
   can reuse registry credentials for their pulls.
2. For each enabled source (registries first, then services), build its connector
   and discover image targets; deduplicate across all sources by digest.
3. Resolve pull credentials per target (connector-specific).
4. Run the core extractor over each image (optionally concurrently).
5. Wrap each SBOM with platform asset context and POST it (unless dry-run).

Progress is reported through the ``image_scanner`` logger (configured by the CLI);
the library never prints directly.
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from .auth.index import RegistryAuthIndex
from .config import Config
from .connectors import ConnectorError, build_connector
from .core.extractors import build_extractor
from .core.scanner import ImageScanner, build_discovery_payload, build_platform_payload
from .core.vulnscan import build_vuln_scanner
from .models import ImageTarget, ScanResult
from .publisher import push_image

log = logging.getLogger("image_scanner.pipeline")


@dataclass
class PipelineResult:
    discovered: list[ImageTarget] = field(default_factory=list)
    scanned: list[ScanResult] = field(default_factory=list)
    payloads: list[dict[str, Any]] = field(default_factory=list)
    cartography_payloads: list[dict[str, Any]] = field(default_factory=list)  # k8s/eks topology
    pushed: int = 0
    cartography_pushed: int = 0  # cluster-topology payloads pushed (k8s/eks sources)
    errors: list[str] = field(default_factory=list)
    per_source: dict[str, int] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        failed = [r for r in self.scanned if not r.ok]
        return {
            "discovered": len(self.discovered),
            "scanned_ok": len([r for r in self.scanned if r.ok]),
            "scanned_failed": len(failed),
            "pushed": self.pushed,
            "clusters_pushed": self.cartography_pushed,
            "by_source": self.per_source,
            "total_components": sum(r.component_count for r in self.scanned if r.ok),
            "total_vulnerabilities": sum(r.vuln_count for r in self.scanned if r.ok),
            "errors": self.errors,
        }


def discover(config: Config, sources_filter: set[str] | None = None) -> tuple[
    list[tuple[Any, ImageTarget]], list[str], dict[str, int], list[Any]
]:
    index = RegistryAuthIndex.from_registries(config.registries)
    pairs: list[tuple[Any, ImageTarget]] = []
    errors: list[str] = []
    per_source: dict[str, int] = {}
    seen: set[str] = set()
    # Connectors that can additionally publish cluster topology (k8s / eks).
    cartographers: list[Any] = []

    enabled = [
        s
        for s in config.all_sources()
        if s.enabled and (not sources_filter or s.name in sources_filter)
    ]
    log.info(
        "discovering from %d source(s): %s",
        len(enabled),
        ", ".join(f"{s.name}({s.type})" for s in enabled) or "(none enabled)",
    )

    for source in enabled:
        log.info("[%s] discovering images…", source.name)
        t0 = time.monotonic()
        try:
            connector = build_connector(source, index=index)
            connector.connect()
            count = 0
            dups = 0
            for target in connector.discover_images():
                if not target.source_id:
                    target.source_id = getattr(connector, "source_id", "")
                if target.source_id:
                    target.discovered_via["source_id"] = target.source_id
                if target.dedup_key in seen:
                    dups += 1
                    continue
                seen.add(target.dedup_key)
                pairs.append((connector, target))
                count += 1
                log.debug("[%s] + %s", source.name, target.reference)
            per_source[source.name] = count
            if hasattr(connector, "cartography_payloads"):
                cartographers.append(connector)
            log.info(
                "[%s] discovered %d image(s) in %.1fs%s",
                source.name,
                count,
                time.monotonic() - t0,
                f" ({dups} duplicate(s) skipped)" if dups else "",
            )
        except (ConnectorError, RuntimeError) as exc:
            log.error("[%s] discovery failed: %s", source.name, exc)
            errors.append(f"[{source.name}] {exc}")

    log.info("discovery complete: %d image(s) to scan", len(pairs))
    return pairs, errors, per_source, cartographers


def _push_cartography(
    config: Config,
    cartographers: list[Any],
    result: PipelineResult,
    should_push: bool,
    *,
    discovery_only: bool = False,
) -> None:
    """Build + publish cluster topology for k8s/eks connectors to
    ``/api/sync/kubernetes-workloads`` (or stash for --no-push)."""
    from k8s_cartographer.publisher import push_to_platform

    for connector in cartographers:
        try:
            payloads = connector.cartography_payloads()
        except Exception as exc:  # noqa: BLE001 — topology must never abort image scans
            log.error("[%s] cluster topology build failed: %s", connector.name, exc)
            result.errors.append(f"[{connector.name}] cartography: {exc}")
            continue
        for payload in payloads:
            if discovery_only:
                payload["discovery_only"] = True
            assets = payload.get("assets", [])
            n_wl = sum(1 for a in assets if a.get("asset_type") == "k8s_workload")
            cluster = next((a["external_id"] for a in assets if a.get("asset_type") == "k8s_cluster"), "?")
            if not should_push:
                result.cartography_payloads.append(payload)  # kept for --no-push / inspection
                continue
            try:
                push_to_platform(config.platform.url, payload)
                result.cartography_pushed += 1
                log.info("✓ cluster topology: %s — %d workload(s) pushed", cluster, n_wl)
            except RuntimeError as exc:
                log.error("✗ cluster topology push failed (%s): %s", cluster, exc)
                result.errors.append(f"[{connector.name}] cartography push {cluster}: {exc}")


def run(
    config: Config,
    sources_filter: set[str] | None = None,
    dry_run: bool = False,
    push: bool | None = None,
    inventory_only: bool = False,
) -> PipelineResult:
    t_start = time.monotonic()
    result = PipelineResult()
    pairs, errors, per_source, cartographers = discover(config, sources_filter)
    result.errors.extend(errors)
    result.per_source = per_source
    result.discovered = [t for _, t in pairs]

    if dry_run:
        log.info("dry-run: discovery only, not scanning")
        return result

    should_push = config.platform.push if push is None else push

    if inventory_only:
        if cartographers:
            _push_cartography(config, cartographers, result, should_push, discovery_only=True)
        for target in result.discovered:
            payload = build_discovery_payload(target)
            if should_push:
                try:
                    push_image(config.platform.url, payload)
                    result.pushed += 1
                except RuntimeError as exc:
                    result.errors.append(f"[{target.source}] inventory push {target.reference}: {exc}")
                    log.error("✗ inventory push failed %s — %s", target.reference, exc)
            else:
                result.payloads.append(payload)
        log.info(
            "inventory refresh complete: discovered=%d pushed=%d clusters=%d errors=%d",
            len(result.discovered), result.pushed, result.cartography_pushed, len(result.errors),
        )
        return result

    # Publish cluster topology (clusters + workloads + image→workload links) for
    # k8s/eks sources, so the platform shows runtime workloads and ties each image
    # to them. Image identity is aligned, so the SBOMs pushed below land on the
    # same container_image assets these relationships point at.
    if cartographers:
        _push_cartography(config, cartographers, result, should_push)

    extractor = build_extractor(config.scanner)
    if not extractor.available():
        log.warning(
            "extractor '%s' not found on PATH — install it or set scanner.extractor; scans will fail",
            extractor.name,
        )
    vuln_scanner = build_vuln_scanner(config.scanner)
    if vuln_scanner is not None and not vuln_scanner.available():
        log.warning(
            "%s not found on PATH — SBOMs will sync WITHOUT vulnerabilities "
            "(install grype or set scanner.scan_vulnerabilities: false)",
            vuln_scanner.name,
        )
        vuln_scanner = None
    if vuln_scanner is not None:
        log.info("vulnerability scanning enabled (%s)", vuln_scanner.name)
    scanner = ImageScanner(extractor, vuln_scanner=vuln_scanner)

    # Resolve credentials in the main thread (connector caches, avoids races),
    # then run extraction concurrently.
    log.info("resolving pull credentials for %d image(s)…", len(pairs))
    for connector, target in pairs:
        if target.auth is None:
            try:
                target.auth = connector.registry_auth_for(target)
            except RuntimeError as exc:
                log.error("[%s] auth for %s failed: %s", target.source, target.reference, exc)
                result.errors.append(f"[{target.source}] auth for {target.reference}: {exc}")

    workers = max(1, int(config.scanner.concurrency))
    total = len(pairs)
    log.info("scanning %d image(s) with %s (concurrency=%d, push=%s)…",
             total, extractor.name, workers, should_push)
    done = 0
    lock = threading.Lock()

    def scan_one(target: ImageTarget) -> ScanResult:
        nonlocal done
        t0 = time.monotonic()
        res = scanner.scan(target)
        pushed = False
        if res.ok:
            payload = build_platform_payload(res)
            # Push immediately, per image, so partial progress survives a crash.
            if should_push:
                try:
                    push_image(config.platform.url, payload)
                    pushed = True
                    with lock:
                        result.pushed += 1
                except RuntimeError as exc:
                    with lock:
                        result.errors.append(f"[{res.target.source}] push {res.target.reference}: {exc}")
                    log.error("✗ push failed %s — %s", res.target.reference, exc)
            else:
                with lock:
                    result.payloads.append(payload)  # kept for --format json / --no-push
        with lock:
            done += 1
            n = done
            if not res.ok:
                result.errors.append(f"[{res.target.source}] scan failed: {res.error}")
        dt = time.monotonic() - t0
        if res.ok:
            vulns = f", {res.vuln_count} vuln(s)" if scanner.vuln_scanner is not None else ""
            tail = "" if not should_push else (" · pushed" if pushed else " · PUSH FAILED")
            log.info(
                "✓ [%d/%d] %s → %d component(s)%s (%.1fs)%s",
                n, total, target.reference, res.component_count, vulns, dt, tail,
            )
            if res.vuln_error:
                log.warning("  vuln scan issue for %s: %s", target.reference, res.vuln_error)
        else:
            log.warning("✗ [%d/%d] %s — %s", n, total, target.reference, res.error)
        return res

    if workers == 1 or total <= 1:
        scanned = [scan_one(t) for _, t in pairs]
    else:
        scanned = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(scan_one, t) for _, t in pairs]
            for fut in as_completed(futures):
                scanned.append(fut.result())
    result.scanned = scanned

    ok_n = len([r for r in scanned if r.ok])
    if should_push:
        log.info("pushed %d/%d SBOM(s) to %s", result.pushed, ok_n, config.platform.url)
    elif ok_n:
        log.info("push disabled (--no-push): built %d payload(s)", len(result.payloads))

    s = result.summary()
    log.info(
        "done in %.1fs · discovered=%d scanned_ok=%d failed=%d pushed=%d clusters=%d components=%d vulnerabilities=%d errors=%d",
        time.monotonic() - t_start,
        s["discovered"], s["scanned_ok"], s["scanned_failed"], s["pushed"],
        s["clusters_pushed"], s["total_components"], s["total_vulnerabilities"], len(result.errors),
    )
    return result


# --------------------------------------------------------------------------- #
# Local CLI mode: scan image references directly (no platform, no config).
# --------------------------------------------------------------------------- #
def parse_image_ref(ref: str) -> ImageTarget:
    """Turn a bare image reference into an ImageTarget (registry/repo/tag/digest)."""
    from .models import split_image_ref

    repo_full, tag, digest = split_image_ref(ref)
    head, _, rest = repo_full.partition("/")
    if rest and ("." in head or ":" in head or head == "localhost"):
        registry, repository = head, rest
    else:
        registry, repository = "docker.io", repo_full
    return ImageTarget(
        reference=ref, registry=registry, repository=repository, tag=tag, digest=digest, source="local"
    )


def run_local(refs: list[str], scanner_cfg) -> "PipelineResult":
    """Scan image references directly with syft (+grype) — no discovery, no push."""
    result = PipelineResult()
    extractor = build_extractor(scanner_cfg)
    if not extractor.available():
        log.warning("extractor '%s' not found on PATH — scans will fail", extractor.name)
    vuln_scanner = build_vuln_scanner(scanner_cfg)
    if vuln_scanner is not None and not vuln_scanner.available():
        log.warning("%s not found on PATH — SBOMs without vulnerabilities", vuln_scanner.name)
        vuln_scanner = None
    scanner = ImageScanner(extractor, vuln_scanner=vuln_scanner)

    total = len(refs)
    for i, ref in enumerate(refs, 1):
        target = parse_image_ref(ref)
        result.discovered.append(target)
        t0 = time.monotonic()
        res = scanner.scan(target)
        result.scanned.append(res)
        dt = time.monotonic() - t0
        if res.ok:
            result.payloads.append(build_platform_payload(res))
            log.info("✓ [%d/%d] %s → %d component(s), %d vuln(s) (%.1fs)",
                     i, total, ref, res.component_count, res.vuln_count, dt)
        else:
            result.errors.append(f"[{ref}] {res.error}")
            log.warning("✗ [%d/%d] %s — %s", i, total, ref, res.error)
    return result


def flatten_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Human-friendly per-target view from a normalized platform payload."""
    asset = (payload.get("assets") or [{}])[0]
    comps = payload.get("components") or []
    by_key: dict[str, dict[str, Any]] = {}
    for comp in comps:
        if comp.get("ref"):
            by_key[comp["ref"]] = comp
        purl = comp.get("purl") or ""
        if purl:
            by_key.setdefault(purl.split("?")[0], comp)
    vulns = []
    malware = []
    for finding in payload.get("findings") or []:
        ftype = finding.get("finding_type")
        if ftype == "cve":
            ref = finding.get("component_ref") or ""
            comp = by_key.get(ref) or by_key.get(ref.split("?")[0]) or {}
            vulns.append({
                "id": finding.get("title", ""),
                "severity": finding.get("severity", ""),
                "package": comp.get("name", ""),
                "version": comp.get("version", ""),
                "fix": finding.get("fix_recommendation", ""),
            })
        elif ftype == "malware":
            ev = finding.get("evidence") or {}
            malware.append({
                "advisory_id": finding.get("title", ""),
                "package": ev.get("package", ""),
                "version": ev.get("version", ""),
                "advisory_url": ev.get("advisory_url", ""),
            })
    return {
        "target": asset.get("external_id") or asset.get("display_name") or "",
        "asset_type": asset.get("asset_type", ""),
        "summary": {"components": len(comps), "vulnerabilities": len(vulns), "malware": len(malware)},
        "components": [
            {"name": c.get("name", ""), "version": c.get("version", ""),
             "ecosystem": c.get("ecosystem", ""), "package_manager": c.get("package_manager", ""),
             "purl": c.get("purl", ""), "license": c.get("license", "")}
            for c in comps
        ],
        "vulnerabilities": vulns,
        "malware": malware,
    }
