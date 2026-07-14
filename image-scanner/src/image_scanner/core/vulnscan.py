"""Vulnerability scanning over an SBOM with Anchore grype.

grype natively consumes a syft SBOM and matches it against its vulnerability
database — so we don't pull or re-catalog the image. We read grype's **native
JSON** (``-o json``) rather than its CycloneDX output, because the CycloneDX
output drops the **fix version** entirely; the native ``vulnerability.fix.versions``
is the only place the recommended upgrade lives. We synthesize CycloneDX-style
vulnerability entries (with the fix in ``recommendation``) so the downstream
``findings_from_cyclonedx`` keeps working and the platform stores the upgrade.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any

from supplydrift_sandbox import NetworkPolicy, SandboxError

from .._sandbox import tool_sandbox


class VulnScanError(RuntimeError):
    """Raised when the vulnerability scanner fails."""


class GrypeVulnScanner:
    name = "grype"

    def __init__(self, grype_bin: str = "grype", timeout: int = 600):
        self.grype_bin = grype_bin
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.grype_bin) is not None

    def scan_sbom(self, sbom: dict[str, Any]) -> list[dict[str, Any]]:
        """Return CycloneDX-style vulnerabilities (incl. the fix) for this SBOM."""
        if not self.available():
            raise VulnScanError(
                f"'{self.grype_bin}' not found on PATH. Install grype "
                "(https://github.com/anchore/grype) or set scanner.scan_vulnerabilities: false."
            )
        with tempfile.NamedTemporaryFile("w", suffix=".cdx.json", delete=False, encoding="utf-8") as fh:
            json.dump(sbom, fh)
            sbom_path = fh.name
        try:
            cmd = [self.grype_bin, f"sbom:{sbom_path}", "-o", "json", "-q"]
            environment = {
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                "GRYPE_DB_AUTO_UPDATE": "false",
            }
            read_paths = [sbom_path]
            configured_db = os.environ.get("GRYPE_DB_CACHE_DIR")
            local_db = configured_db or os.path.join(os.path.expanduser("~"), ".cache", "grype", "db")
            if os.path.isdir(local_db):
                environment["GRYPE_DB_CACHE_DIR"] = local_db
                read_paths.append(local_db)
            try:
                completed = tool_sandbox.run(
                    "grype",
                    cmd,
                    read_paths=read_paths,
                    environment=environment,
                    network_policy=NetworkPolicy.BLOCKED,
                    timeout_seconds=self.timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise VulnScanError(f"grype timed out after {self.timeout}s") from exc
            except (OSError, SandboxError) as exc:
                raise VulnScanError(f"grype sandbox failed: {exc}") from exc
            if completed.returncode != 0:
                raise VulnScanError(
                    f"grype failed (exit {completed.returncode}): {completed.stderr.strip()[:500]}"
                )
            try:
                doc = json.loads(completed.stdout or "{}")
            except json.JSONDecodeError as exc:
                raise VulnScanError("grype returned invalid JSON") from exc
            return grype_matches_to_cyclonedx(doc)
        finally:
            try:
                os.unlink(sbom_path)
            except OSError:
                pass


def grype_matches_to_cyclonedx(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert grype native ``matches[]`` into CycloneDX vulnerability entries.

    The recommended upgrade (``vulnerability.fix.versions``) is folded into
    ``recommendation`` — it is absent from grype's own CycloneDX output.
    """
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for match in doc.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vid = vuln.get("id") or ""
        purl = artifact.get("purl") or ""
        key = (vid, purl)
        if not vid or key in seen:
            continue
        seen.add(key)
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


def build_vuln_scanner(scanner: Any) -> GrypeVulnScanner | None:
    """Construct the vulnerability scanner from config (None when disabled)."""
    if not getattr(scanner, "scan_vulnerabilities", True):
        return None
    return GrypeVulnScanner(grype_bin=scanner.grype_bin, timeout=scanner.timeout)
