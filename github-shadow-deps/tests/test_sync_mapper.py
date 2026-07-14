"""Tests for the GitHub scan -> platform payload mapper."""
from __future__ import annotations

from github_inventory.models import Category, Finding, ScanResult, Severity
from github_inventory.sync.connector import RepoTarget
from github_inventory.sync.mapper import build_discovery_payload, build_payload


def _repo() -> RepoTarget:
    return RepoTarget(
        full_name="acme/payments-api",
        owner="acme",
        repo="payments-api",
        clone_url="https://github.com/acme/payments-api.git",
        html_url="https://github.com/acme/payments-api",
        default_branch="main",
        visibility="public",
    )


def _finding(category, severity, dep, file="x.yml", line=1) -> Finding:
    return Finding(
        file_path=file, line_number=line, category=category, severity=severity,
        pattern_id="p1", matched_text=f"uses: {dep}", extracted_dep=dep,
        description="phantom dep", scanner_name="cicd",
    )


def test_build_payload_repository_asset():
    result = ScanResult(findings=[_finding(Category.CICD_TOOL, Severity.HIGH, "actions/checkout@v3")], files_scanned=10)
    payload = build_payload(_repo(), result, "acme-org")
    asset = payload["assets"][0]
    assert asset["asset_type"] == "repository" and asset["provider"] == "github"
    assert asset["external_id"] == "github.com/acme/payments-api"
    assert asset["owner"] == "acme"  # pulled from the connector/repo, not blank
    assert asset["details"]["org_name"] == "acme" and asset["details"]["repo_name"] == "payments-api"


def test_action_becomes_component_and_finding():
    result = ScanResult(findings=[_finding(Category.CICD_TOOL, Severity.HIGH, "actions/checkout@v3")])
    payload = build_payload(_repo(), result, "acme-org")
    comp = payload["components"][0]
    assert comp["name"] == "actions/checkout" and comp["version"] == "v3"
    assert comp["ecosystem"] == "github-actions"
    assert comp["purl"] == "pkg:githubactions/actions/checkout@v3"
    finding = payload["findings"][0]
    assert finding["finding_type"] == "cicd-tool" and finding["severity"] == "high"
    assert finding["component_ref"] == comp["ref"]
    assert finding["evidence"]["file"] == "x.yml"


def test_components_deduped_findings_kept():
    # Same dep in two files -> one component, two findings (platform dedups later).
    result = ScanResult(findings=[
        _finding(Category.CICD_TOOL, Severity.HIGH, "actions/checkout@v3", "a.yml", 1),
        _finding(Category.CICD_TOOL, Severity.HIGH, "actions/checkout@v3", "b.yml", 2),
        _finding(Category.SCRIPT_INSTALLATION, Severity.CRITICAL, "curl https://x.sh | bash", "s.sh", 5),
    ])
    payload = build_payload(_repo(), result, "s")
    assert len(payload["components"]) == 2          # checkout + curl
    assert len(payload["findings"]) == 3            # all detections
    curl = next(c for c in payload["components"] if c["ecosystem"] == "generic")
    assert curl["purl"].startswith("pkg:generic/")


def test_scan_metadata_counts():
    result = ScanResult(findings=[_finding(Category.CICD_TOOL, Severity.LOW, "a/b@v1")], files_scanned=3, scan_duration_ms=12.0)
    meta = build_payload(_repo(), result, "s")["scan_metadata"]
    assert meta["files_scanned"] == 3 and meta["component_count"] == 1 and meta["finding_count"] == 1


def test_platform_connector_id_is_preserved():
    repo = _repo()
    repo.source_id = "connector-1"
    payload = build_payload(repo, ScanResult(), "acme-org")
    assert payload["connector"]["id"] == "connector-1"

    discovery = build_discovery_payload(repo, "acme-org")
    assert discovery["discovery_only"] is True
    assert discovery["connector"]["id"] == "connector-1"
    assert discovery["components"] == [] and discovery["findings"] == []
