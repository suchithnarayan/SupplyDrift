"""The source-agnostic core scanner.

Given an ``ImageTarget`` it runs the configured extractor backend to produce a
CycloneDX SBOM and (optionally) grype vulnerabilities, then extracts just the
fields the platform needs into a COMPACT normalized payload — package
name/version/purl/ecosystem/type and CVE id/severity/fix — so the upload to
``/api/sync/container-images`` is small (and gzip-compressed by the publisher),
not the full raw SBOM document.
"""
from __future__ import annotations

import re
from typing import Any

from ..models import ImageTarget, ScanResult
from .extractors.base import ExtractorError, SbomExtractor

_PURL_TYPE_RE = re.compile(r"^pkg:([^/@?#]+)/")
# grype severities -> platform buckets (matches platform normalize_severity).
_SEVERITY_MAP = {"negligible": "low", "none": "info", "moderate": "medium", "unknown": "info", "": "info"}


def ecosystem_from_purl(purl: str) -> str:
    """pkg:npm/lodash@4 -> 'npm', pkg:deb/ubuntu/openssl@3 -> 'deb'."""
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


def registry_type(registry: str) -> str:
    reg = (registry or "").lower()
    if "amazonaws" in reg or ".ecr." in reg:
        return "ecr"
    if "ghcr.io" in reg:
        return "ghcr"
    if reg in {"docker.io", "registry-1.docker.io", "index.docker.io"}:
        return "dockerhub"
    if reg.startswith("quay.io"):
        return "quay"
    return "other"


_PROVIDER_BY_REGISTRY_TYPE = {
    "ecr": "aws_ecr",
    "ghcr": "github_ghcr",
    "dockerhub": "docker_hub",
    "harbor": "harbor",
    "quay": "quay",
    "other": "registry",
}


def provider_for(target: ImageTarget) -> str:
    if target.provider:
        return target.provider
    return _PROVIDER_BY_REGISTRY_TYPE.get(registry_type(target.registry), "registry")


def _count_components(cyclonedx: dict[str, Any]) -> int:
    components = cyclonedx.get("components")
    return len(components) if isinstance(components, list) else 0


class ImageScanner:
    """Runs an SBOM extractor (and optional vulnerability scanner) over targets."""

    def __init__(self, extractor: SbomExtractor, vuln_scanner: Any = None):
        self.extractor = extractor
        self.vuln_scanner = vuln_scanner

    def scan(self, target: ImageTarget) -> ScanResult:
        try:
            cyclonedx = self.extractor.extract(target.reference, target.auth)
        except ExtractorError as exc:
            return ScanResult(target=target, cyclonedx={}, extractor=self.extractor.name, error=str(exc))

        vuln_count = 0
        vuln_error = ""
        if self.vuln_scanner is not None:
            try:
                vulns = self.vuln_scanner.scan_sbom(cyclonedx)
                if vulns:
                    # Graft CVEs onto the SBOM; the platform ingests them as findings.
                    cyclonedx["vulnerabilities"] = vulns
                    vuln_count = len(vulns)
            except RuntimeError as exc:
                # A vuln-scan failure must not drop the SBOM — keep the SBOM, note it.
                vuln_error = str(exc)

        return ScanResult(
            target=target,
            cyclonedx=cyclonedx,
            component_count=_count_components(cyclonedx),
            vuln_count=vuln_count,
            extractor=self.extractor.name,
            vuln_error=vuln_error,
        )


def _components_from_cyclonedx(cyclonedx: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract minimal component + usage records from the CycloneDX components."""
    components: list[dict[str, Any]] = []
    usages: list[dict[str, Any]] = []
    for index, comp in enumerate(cyclonedx.get("components") or []):
        props = _props(comp)
        purl = comp.get("purl", "") or ""
        ref = comp.get("bom-ref") or purl or comp.get("name") or f"component-{index}"
        # ecosystem (npm/pypi/deb/apk/golang...) from the purl; package type
        # (deb/python/npm/go-module/java-archive...) from syft's own label.
        ecosystem = _prop(props, "supplydrift:ecosystem") or ecosystem_from_purl(purl) or comp.get("type", "")
        pkg_type = _prop(props, "syft:package:type", "supplydrift:package_manager", "package_manager") or ecosystem
        components.append({
            "ref": ref,
            "name": comp.get("name", "") or purl or ref,
            "version": comp.get("version", ""),
            "ecosystem": ecosystem,
            "package_manager": pkg_type,
            "purl": purl,
            "cpe": comp.get("cpe", "") or _prop(props, "syft:cpe23"),
            "license": _license_str(comp),
        })
        usages.append({
            "asset_ref": "image_asset",
            "component_ref": ref,
            "source": "image_scan",
            "evidence_path": _prop(props, "syft:location:0:path", "supplydrift:path", "evidence_path"),
            "layer_digest": _prop(props, "syft:location:0:layerID", "syft:location:0:layer"),
            "package_manager": pkg_type,
            "evidence": {"type": comp.get("type", ""), "scope": comp.get("scope", "")},
        })
    return components, usages


def _findings_from_cyclonedx(cyclonedx: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract minimal CVE findings from the grype-populated vulnerabilities."""
    findings: list[dict[str, Any]] = []
    for vuln in cyclonedx.get("vulnerabilities") or []:
        ratings = vuln.get("ratings") or []
        severity = _normalize_severity(ratings[0].get("severity") if ratings else "")
        vid = vuln.get("id") or vuln.get("bom-ref") or "Vulnerability"
        affects = vuln.get("affects") or []
        refs = [a.get("ref") for a in affects if a.get("ref")] or [None]
        for ref in refs:
            findings.append({
                "asset_ref": "image_asset",
                "component_ref": ref,
                "finding_type": "cve",
                "severity": severity,
                "title": vid,
                "description": vuln.get("description", ""),
                "fix_recommendation": vuln.get("recommendation", ""),
                "evidence": {"source": vuln.get("source", {}), "ratings": ratings},
            })
    return findings


def align_image_asset_identity(payload: dict[str, Any]) -> dict[str, Any]:
    """Rewrite ``container_image`` assets in a cartography payload to the SAME
    ``provider`` + ``external_id`` the image-SBOM pipeline uses.

    The platform keys asset identity on (asset_type, provider, external_id), so
    without this the cluster-topology image asset (from k8s-cartographer) and the
    SBOM-bearing image asset (from this scanner) would be two separate assets.
    Aligning them makes the runtime workload link and the SBOM converge on ONE
    container_image asset. Mutates and returns ``payload``.
    """
    for asset in payload.get("assets", []):
        if asset.get("asset_type") != "container_image":
            continue
        details = asset.get("details") or {}
        target = ImageTarget(
            reference=asset.get("external_id", ""),
            registry=details.get("registry_url", ""),
            repository=details.get("repository", ""),
            tag=details.get("tag", ""),
            digest=details.get("digest", ""),
        )
        asset["provider"] = provider_for(target)
        asset["external_id"] = target.dedup_key
    return payload


def build_platform_payload(result: ScanResult) -> dict[str, Any]:
    """Build a COMPACT normalized payload for ``/api/sync/container-images``.

    Instead of shipping the whole CycloneDX document, the runner extracts only the
    fields the platform stores — package name/version/purl/**ecosystem**/**type**
    and CVE id/severity/fix — into the platform's normalized
    ``{assets, components, component_usages, findings}`` shape. The publisher
    gzip-compresses it. The platform ingests it directly via ``ingest()``.
    """
    target = result.target
    cyclonedx = result.cyclonedx or {}
    external_id = target.dedup_key
    display = f"{target.repository}:{target.tag}" if target.tag else target.repository
    if target.digest:
        display = f"{display}@{target.digest[:19]}" if display else target.digest[:19]

    components, usages = _components_from_cyclonedx(cyclonedx)
    findings = _findings_from_cyclonedx(cyclonedx)
    connector = {
        "name": target.source or "Registry Image SBOM",
        "connector_type": "registry_scanner",
        "status": "manual",
    }
    if target.source_id:
        connector["id"] = target.source_id

    return {
        "connector": connector,
        "source_name": target.source or "image-scanner",
        "scan_metadata": {
            "scanner_version": f"image-scanner ({result.extractor})",
            "component_count": result.component_count,
            "vulnerability_count": result.vuln_count,
        },
        "assets": [{
            "ref": "image_asset",
            "asset_type": "container_image",
            "provider": provider_for(target),
            "external_id": external_id,
            "display_name": display or target.reference,
            "details": {
                "registry_type": registry_type(target.registry),
                "registry_url": target.registry,
                "repository": target.repository,
                "image_name": target.image_name,
                "tag": target.tag,
                "digest": target.digest,
                "pushed_at": target.pushed_at,
            },
            "raw_metadata": {
                "discovered_via": target.discovered_via,
                "source": target.source,
                "extractor": result.extractor,
            },
        }],
        "components": components,
        "component_usages": usages,
        "findings": findings,
    }


def build_discovery_payload(target: ImageTarget) -> dict[str, Any]:
    """Build an inventory-only payload for a discovered image.

    Refresh jobs should prove that a source can be reached and update the asset
    inventory without running Syft/Grype. The platform keeps these assets in the
    ``discovered`` scan status until a later full scan upgrades them.
    """
    external_id = target.dedup_key
    display = f"{target.repository}:{target.tag}" if target.tag else target.repository
    if target.digest:
        display = f"{display}@{target.digest[:19]}" if display else target.digest[:19]
    connector = {
        "name": target.source or "Registry Image SBOM",
        "connector_type": "registry_scanner",
        "status": "manual",
    }
    if target.source_id:
        connector["id"] = target.source_id
    return {
        "connector": connector,
        "source_name": target.source or "image-scanner",
        "discovery_only": True,
        "scan_metadata": {
            "scanner_version": "image-scanner discovery",
            "component_count": 0,
            "vulnerability_count": 0,
        },
        "assets": [{
            "ref": "image_asset",
            "asset_type": "container_image",
            "provider": provider_for(target),
            "external_id": external_id,
            "display_name": display or target.reference,
            "details": {
                "registry_type": registry_type(target.registry),
                "registry_url": target.registry,
                "repository": target.repository,
                "image_name": target.image_name,
                "tag": target.tag,
                "digest": target.digest,
                "pushed_at": target.pushed_at,
            },
            "raw_metadata": {
                "discovered_via": target.discovered_via,
                "source": target.source,
                "extractor": "inventory-refresh",
            },
        }],
        "components": [],
        "component_usages": [],
        "findings": [],
    }
