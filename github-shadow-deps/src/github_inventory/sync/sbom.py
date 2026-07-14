"""Optional syft (SBOM) + grype (CVE) pass over a cloned repo.

Mirrors the image-scanner's daemonless approach: run syft on the repo directory
to get declared dependencies as CycloneDX, feed that to grype for CVEs, then
extract the minimal fields the platform stores. Degrades gracefully — if syft (or
grype) isn't installed, the repo scan still ships the phantom-dependency findings.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

from supplydrift_sandbox import NetworkPolicy, SandboxError, SandboxExecutor

log = logging.getLogger("gbom_sync.sbom")
tool_sandbox = SandboxExecutor(logger=logging.getLogger("gbom_sync.sandbox"))

_PURL_TYPE_RE = re.compile(r"^pkg:([^/@?#]+)/")
_SEVERITY_MAP = {"negligible": "low", "none": "info", "moderate": "medium", "unknown": "info", "": "info"}

def syft_available(syft_bin: str = "syft") -> bool:
    return shutil.which(syft_bin) is not None


def grype_available(grype_bin: str = "grype") -> bool:
    return shutil.which(grype_bin) is not None


def ecosystem_from_purl(purl: str) -> str:
    match = _PURL_TYPE_RE.match((purl or "").strip())
    return match.group(1).lower() if match else ""


def _props(component: dict[str, Any]) -> dict[str, str]:
    return {p.get("name"): p.get("value") for p in (component.get("properties") or []) if p.get("name")}


def _prop(props: dict[str, str], *keys: str) -> str:
    for key in keys:
        if props.get(key):
            return props[key]
    return ""


def _license_str(component: dict[str, Any]) -> str:
    out: list[str] = []
    for entry in component.get("licenses") or []:
        lic = entry.get("license") or {}
        value = lic.get("id") or lic.get("name") or entry.get("expression")
        if value:
            out.append(value)
    return ", ".join(out)


def _normalize_severity(value: str | None) -> str:
    v = (value or "").strip().lower()
    return _SEVERITY_MAP.get(v, v)


def extract_repo_sbom(
    root: str,
    syft_bin: str = "syft",
    grype_bin: str = "grype",
    scan_vulnerabilities: bool = True,
    timeout: int = 600,
) -> dict[str, Any] | None:
    """Run syft over the repo dir; merge grype CVEs. Returns CycloneDX or None."""
    if not syft_available(syft_bin):
        return None
    try:
        completed = tool_sandbox.run(
            "syft",
            [syft_bin, f"dir:{root}", "-o", "cyclonedx-json", "-q"],
            read_paths=[root],
            environment={"SYFT_CHECK_FOR_APP_UPDATE": "false"},
            network_policy=NetworkPolicy.BLOCKED,
            timeout_seconds=timeout,
        )
        if completed.returncode != 0:
            log.warning("syft failed for %s: %s", root, (completed.stderr or "")[:200])
            return None
        cyclonedx = json.loads(completed.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, SandboxError) as exc:
        log.warning("syft error for %s: %s", root, exc)
        return None

    if scan_vulnerabilities and grype_available(grype_bin):
        vulns = _run_grype(cyclonedx, grype_bin, timeout)
        if vulns:
            cyclonedx["vulnerabilities"] = vulns
    return cyclonedx


def _run_grype(cyclonedx: dict[str, Any], grype_bin: str, timeout: int) -> list[dict[str, Any]]:
    path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".cdx.json", delete=False, encoding="utf-8") as fh:
            json.dump(cyclonedx, fh)
            path = fh.name
        environment = {
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",
            "GRYPE_DB_AUTO_UPDATE": "false",
        }
        read_paths = [path]
        configured_db = os.environ.get("GRYPE_DB_CACHE_DIR")
        local_db = configured_db or os.path.join(os.path.expanduser("~"), ".cache", "grype", "db")
        if os.path.isdir(local_db):
            environment["GRYPE_DB_CACHE_DIR"] = local_db
            read_paths.append(local_db)
        # Native JSON, not cyclonedx-json: the latter drops the fix version.
        completed = tool_sandbox.run(
            "grype",
            [grype_bin, f"sbom:{path}", "-o", "json", "-q"],
            read_paths=read_paths,
            environment=environment,
            network_policy=NetworkPolicy.BLOCKED,
            timeout_seconds=timeout,
        )
        if completed.returncode != 0:
            log.warning("grype failed: %s", (completed.stderr or "")[:200])
            return []
        return _grype_matches_to_cyclonedx(json.loads(completed.stdout or "{}"))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, SandboxError) as exc:
        log.warning("grype error: %s", exc)
        return []
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _grype_matches_to_cyclonedx(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """grype native matches -> CycloneDX vulns, folding fix.versions into recommendation."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for match in doc.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vid = vuln.get("id") or ""
        purl = artifact.get("purl") or ""
        if not vid or (vid, purl) in seen:
            continue
        seen.add((vid, purl))
        fix_versions = (vuln.get("fix") or {}).get("versions") or []
        out.append({
            "id": vid,
            "source": {"name": vuln.get("namespace", ""), "url": vuln.get("dataSource", "")},
            "ratings": [{"severity": str(vuln.get("severity") or "unknown").lower()}],
            "affects": [{"ref": purl}] if purl else [],
            "description": vuln.get("description", ""),
            "recommendation": (
                f"Upgrade {artifact.get('name', 'the package')} to {', '.join(fix_versions)}"
                if fix_versions else ""
            ),
        })
    return out


def sbom_components(cyclonedx: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract minimal {ref,name,version,ecosystem,package_manager,purl,...} components."""
    out: list[dict[str, Any]] = []
    for index, comp in enumerate(cyclonedx.get("components") or []):
        props = _props(comp)
        purl = comp.get("purl", "") or ""
        ref = comp.get("bom-ref") or purl or comp.get("name") or f"component-{index}"
        ecosystem = _prop(props, "supplydrift:ecosystem") or ecosystem_from_purl(purl) or comp.get("type", "")
        pkg_type = _prop(props, "syft:package:type", "package_manager") or ecosystem
        out.append({
            "ref": ref,
            "name": comp.get("name", "") or purl or ref,
            "version": comp.get("version", ""),
            "ecosystem": ecosystem,
            "package_manager": pkg_type,
            "purl": purl,
            "cpe": comp.get("cpe", "") or _prop(props, "syft:cpe23"),
            "license": _license_str(comp),
            "evidence_path": _prop(props, "syft:location:0:path", "supplydrift:path", "evidence_path"),
        })
    return out


def sbom_findings(cyclonedx: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract CVE findings (component_ref + severity + fix) from grype vulnerabilities."""
    findings: list[dict[str, Any]] = []
    for vuln in cyclonedx.get("vulnerabilities") or []:
        ratings = vuln.get("ratings") or []
        severity = _normalize_severity(ratings[0].get("severity") if ratings else "")
        vid = vuln.get("id") or vuln.get("bom-ref") or "Vulnerability"
        affects = vuln.get("affects") or []
        refs = [a.get("ref") for a in affects if a.get("ref")] or [None]
        for ref in refs:
            findings.append({
                "component_ref": ref,
                "finding_type": "cve",
                "severity": severity,
                "title": vid,
                "description": vuln.get("description", ""),
                "fix_recommendation": vuln.get("recommendation", ""),
                "evidence": {"source": vuln.get("source", {}), "ratings": ratings},
            })
    return findings
