"""Convert a repo scan into the platform's normalized ingest payload.

Each detection becomes BOTH a repository SBOM **component** (the phantom
dependency — e.g. ``actions/checkout@v3``) and a **finding** (the security issue
— unpinned action, ``curl|bash``, ...). The platform's ``/api/sync/repositories``
accepts this normalized shape (``{assets, components, component_usages, findings}``)
directly.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from github_inventory.models import Category, Finding, ScanResult
from github_inventory.redaction import redact_value

from .connector import RepoTarget
from .sbom import sbom_components, sbom_findings

# Category -> (ecosystem, package_manager). None ecosystem means "infer / generic".
_ECOSYSTEM_BY_CATEGORY: dict[Category, str] = {
    Category.CICD_TOOL: "github-actions",
    Category.GIT_DEPENDENCY: "git",
    Category.CONTAINER_IMAGE: "oci",
    Category.UNMANAGED_PACKAGE: "generic",
    Category.PACKAGE_SCRIPT: "npm",
    Category.MCP_SERVER: "npm",
    Category.AGENT_PLUGIN: "generic",
}

_ACTION_RE = re.compile(r"^(?P<repo>[\w.-]+/[\w.-]+)@(?P<ref>\S+)$")


def _slug(text: str) -> str:
    return quote(re.sub(r"\s+", "-", text.strip())[:200], safe="")


def _component_for(finding: Finding) -> dict[str, Any]:
    dep = (finding.extracted_dep or finding.matched_text or "unknown").strip()
    ecosystem = _ECOSYSTEM_BY_CATEGORY.get(finding.category, "generic")
    name = dep
    version = ""
    purl = ""

    if finding.category is Category.CICD_TOOL:
        m = _ACTION_RE.match(dep)
        if m:
            name, version = m.group("repo"), m.group("ref")
            purl = f"pkg:githubactions/{name}@{version}"
    if not purl:
        purl = f"pkg:generic/{_slug(name)}"

    ref = purl or f"{ecosystem}:{name}"
    return {
        "ref": ref,
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "package_manager": ecosystem,
        "purl": purl,
    }


def _asset_for(repo: RepoTarget) -> dict[str, Any]:
    return {
        "ref": "repo",
        "asset_type": "repository",
        "provider": "github",
        "external_id": f"github.com/{repo.full_name}",
        "display_name": repo.full_name,
        "owner": repo.owner,
        "tags": [repo.visibility] if repo.visibility else [],
        "details": {
            "git_provider": "github",
            "org_name": repo.owner,
            "repo_name": repo.repo,
            "full_name": repo.full_name,
            "repo_url": repo.html_url,
            "default_branch": repo.default_branch,
            "visibility": repo.visibility,
        },
        "raw_metadata": {"discovered_via": repo.discovered_via, "pushed_at": repo.pushed_at},
    }


def _connector_for(repo: RepoTarget, source_name: str) -> dict[str, Any]:
    connector = {"name": source_name, "connector_type": "repo_scanner"}
    if repo.source_id:
        connector["id"] = repo.source_id
    return connector


def build_discovery_payload(repo: RepoTarget, source_name: str) -> dict[str, Any]:
    """Build an inventory-only repository payload without cloning or scanning."""
    payload = {
        "source_name": source_name,
        "connector": _connector_for(repo, source_name),
        "discovery_only": True,
        "scan_metadata": {
            "scanner_version": "github-shadow-deps discovery",
            "component_count": 0,
            "finding_count": 0,
        },
        "assets": [_asset_for(repo)],
        "components": [],
        "component_usages": [],
        "findings": [],
    }
    return redact_value(payload)


def build_payload(
    repo: RepoTarget,
    result: ScanResult,
    source_name: str,
    cyclonedx: dict[str, Any] | None = None,
) -> dict[str, Any]:
    asset = _asset_for(repo)

    components: dict[str, dict[str, Any]] = {}
    usages: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for finding in result.findings:
        f = finding.public_copy()
        comp = _component_for(f)
        components.setdefault(comp["ref"], comp)
        evidence_path = f"{f.file_path}:{f.line_number}"
        usages.append(
            {
                "asset_ref": "repo",
                "component_ref": comp["ref"],
                "source": "repo_scan",
                "evidence_path": evidence_path,
                "package_manager": comp["package_manager"],
                "evidence": {"category": f.category.value, "pattern_id": f.pattern_id},
            }
        )
        recommendation = (f.enrichment or {}).get("recommendation", "") if f.enrichment else ""
        findings.append(
            {
                "asset_ref": "repo",
                "component_ref": comp["ref"],
                "finding_type": f.category.value,
                "severity": f.severity.value,
                "title": f"{f.category.value}: {f.extracted_dep}"[:200],
                "description": f.description,
                "fix_recommendation": recommendation,
                "evidence": {
                    "file": f.file_path,
                    "line": f.line_number,
                    "pattern_id": f.pattern_id,
                    "matched_text": (f.matched_text or "")[:500],
                    "scanner": f.scanner_name,
                    "category": f.category.value,
                    "confidence": f.confidence,
                    "analysis_source": f.analysis_source,
                    "sensitive": f.sensitive,
                },
            }
        )

    phantom_component_count = len(components)
    vuln_count = 0
    # Merge the syft SBOM (declared deps) + grype CVEs, deduped against the
    # phantom-dependency components by ref/purl.
    if cyclonedx:
        for comp in sbom_components(cyclonedx):
            ref = comp["ref"]
            evidence_path = comp.pop("evidence_path", "")
            if ref not in components:
                components[ref] = comp
            usages.append({
                "asset_ref": "repo",
                "component_ref": ref,
                "source": "repo_sbom",
                "evidence_path": evidence_path,
                "package_manager": comp.get("package_manager", ""),
                "evidence": {"sbom": "syft"},
            })
        for cve in sbom_findings(cyclonedx):
            findings.append({"asset_ref": "repo", **cve})
            vuln_count += 1

    payload = {
        "source_name": source_name,
        "connector": _connector_for(repo, source_name),
        "scan_metadata": {
            "scanner_version": "github-shadow-deps",
            "files_scanned": result.files_scanned,
            "duration_ms": result.scan_duration_ms,
            "component_count": len(components),
            "phantom_dependency_count": phantom_component_count,
            "vulnerability_count": vuln_count,
            "finding_count": len(findings),
        },
        "assets": [asset],
        "components": list(components.values()),
        "component_usages": usages,
        "findings": findings,
    }
    # Syft/Grype parse attacker-controlled repositories and may echo URLs or
    # configuration values into components, evidence, and vulnerability text.
    # Redact the complete persistence payload, not only native Finding objects.
    return redact_value(payload)
