"""syft+grype SBOM merged with phantom-dependency findings (deduped)."""
from __future__ import annotations

from github_inventory.models import Category, Finding, ScanResult, Severity
from github_inventory.sync.connector import RepoTarget
from github_inventory.sync.mapper import build_payload
from github_inventory.sync.sbom import ecosystem_from_purl, sbom_components, sbom_findings


def _repo() -> RepoTarget:
    return RepoTarget(
        full_name="acme/api", owner="acme", repo="api",
        clone_url="https://github.com/acme/api.git", html_url="https://github.com/acme/api",
        default_branch="main", visibility="public",
    )


def _finding(cat, sev, dep) -> Finding:
    return Finding(file_path="ci.yml", line_number=1, category=cat, severity=sev,
                   pattern_id="p", matched_text=f"uses {dep}", extracted_dep=dep,
                   description="d", scanner_name="s")


CDX = {
    "components": [
        {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15",
         "properties": [{"name": "syft:package:type", "value": "npm"},
                        {"name": "syft:location:0:path", "value": "package-lock.json"}]},
        {"type": "library", "name": "flask", "version": "2.0.0", "purl": "pkg:pypi/flask@2.0.0",
         "properties": [{"name": "syft:package:type", "value": "python"}]},
    ],
    "vulnerabilities": [
        {"id": "CVE-2019-10744", "ratings": [{"severity": "critical"}],
         "affects": [{"ref": "pkg:npm/lodash@4.17.15"}], "recommendation": "upgrade lodash"},
    ],
}


def test_ecosystem_from_purl():
    assert ecosystem_from_purl("pkg:npm/lodash@4") == "npm"
    assert ecosystem_from_purl("pkg:pypi/flask@2") == "pypi"
    assert ecosystem_from_purl("") == ""


def test_sbom_components_and_findings():
    comps = sbom_components(CDX)
    assert {c["name"] for c in comps} == {"lodash", "flask"}
    lodash = next(c for c in comps if c["name"] == "lodash")
    assert lodash["ecosystem"] == "npm" and lodash["package_manager"] == "npm"
    assert lodash["evidence_path"] == "package-lock.json"
    finds = sbom_findings(CDX)
    assert finds[0]["title"] == "CVE-2019-10744" and finds[0]["severity"] == "critical"
    assert finds[0]["component_ref"] == "pkg:npm/lodash@4.17.15"


def test_build_payload_merges_phantom_and_sbom():
    result = ScanResult(findings=[_finding(Category.CICD_TOOL, Severity.HIGH, "actions/checkout@v3")])
    payload = build_payload(_repo(), result, "acme", cyclonedx=CDX)
    names = {c["name"] for c in payload["components"]}
    assert "actions/checkout" in names          # phantom dep
    assert {"lodash", "flask"} <= names          # syft declared deps
    types = {f["finding_type"] for f in payload["findings"]}
    assert "cicd-tool" in types and "cve" in types
    md = payload["scan_metadata"]
    assert md["phantom_dependency_count"] == 1 and md["vulnerability_count"] == 1


def test_dedup_same_ref():
    cdx = {"components": [{"name": "actions/checkout", "version": "v3",
                          "purl": "pkg:githubactions/actions/checkout@v3"}], "vulnerabilities": []}
    result = ScanResult(findings=[_finding(Category.CICD_TOOL, Severity.HIGH, "actions/checkout@v3")])
    payload = build_payload(_repo(), result, "acme", cyclonedx=cdx)
    refs = [c["ref"] for c in payload["components"]]
    assert refs.count("pkg:githubactions/actions/checkout@v3") == 1  # merged, not duplicated


def test_no_cyclonedx_is_unchanged():
    result = ScanResult(findings=[_finding(Category.CICD_TOOL, Severity.HIGH, "actions/checkout@v3")])
    payload = build_payload(_repo(), result, "acme")  # phantom-deps only
    assert payload["scan_metadata"]["vulnerability_count"] == 0
    assert len(payload["components"]) == 1 and len(payload["findings"]) == 1
