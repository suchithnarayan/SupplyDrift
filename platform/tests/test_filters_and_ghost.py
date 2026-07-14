"""Ghost-dependency dashboard metric, the new list filters, and the per-asset
CVE/ghost finding split.
"""
from __future__ import annotations

# A repository with one manifest package (syft: repo_sbom) and one ghost
# dependency the gbom scanner found non-traditionally (repo_scan only), plus a CVE
# on the manifest package and a shadow-dependency finding on the ghost one.
REPO_PAYLOAD = {
    "connector": {"name": "acme/app", "connector_type": "repo_scanner"},
    "scan_metadata": {"started_at": "2026-06-11T00:00:00+00:00", "status": "completed"},
    "assets": [{
        "ref": "repo", "asset_type": "repository", "provider": "github",
        "external_id": "acme/app", "display_name": "acme/app",
    }],
    "components": [
        {"ref": "pkgA", "name": "left-pad", "version": "1.0.0", "ecosystem": "npm",
         "purl": "pkg:npm/left-pad@1.0.0"},
        {"ref": "pkgB", "name": "install.sh", "version": "", "ecosystem": "generic",
         "purl": "pkg:generic/install.sh"},
    ],
    "component_usages": [
        {"asset_ref": "repo", "component_ref": "pkgA", "source": "repo_sbom",
         "evidence": {"sbom": "syft"}},
        {"asset_ref": "repo", "component_ref": "pkgB", "source": "repo_scan",
         "evidence": {"category": "script-installation", "pattern_id": "curl-bash"}},
    ],
    "findings": [
        {"asset_ref": "repo", "component_ref": "pkgA", "finding_type": "cve",
         "severity": "high", "title": "CVE-2020-0001", "description": "vuln in left-pad"},
        {"asset_ref": "repo", "component_ref": "pkgB", "finding_type": "script-installation",
         "severity": "medium", "title": "curl | bash install"},
    ],
}


def _repo_asset_id(store):
    return store.list_assets({"asset_type": ["repository"]})[0]["id"]


def test_ghost_metric_in_summary(empty_store):
    s = empty_store
    s.ingest(REPO_PAYLOAD)
    ghost = s.summary()["ghost"]
    # 2 repo packages; only pkgB (repo_scan, no repo_sbom) is ghost -> 50%.
    assert ghost["repo_packages"] == 2
    assert ghost["ghost_packages"] == 1
    assert ghost["percent"] == 50.0


def test_ghost_metric_empty_store(empty_store):
    ghost = empty_store.summary()["ghost"]
    assert ghost == {"repo_packages": 0, "ghost_packages": 0, "percent": 0.0}


def test_ghost_excludes_packages_syft_also_declares(empty_store):
    s = empty_store
    s.ingest(REPO_PAYLOAD)
    # Re-declare pkgB via syft too -> it is no longer "missed by syft" -> 0 ghost.
    s.ingest({
        **REPO_PAYLOAD,
        "component_usages": [
            {"asset_ref": "repo", "component_ref": "pkgB", "source": "repo_sbom",
             "evidence": {"sbom": "syft"}},
        ],
        "findings": [],
    })
    assert s.summary()["ghost"]["ghost_packages"] == 0


def test_asset_findings_kind_split(empty_store):
    s = empty_store
    s.ingest(REPO_PAYLOAD)
    aid = _repo_asset_id(s)
    cve = s.asset_findings(aid, {"kind": ["cve"]})
    ghost = s.asset_findings(aid, {"kind": ["ghost"]})
    assert [f["finding_type"] for f in cve] == ["cve"]
    assert [f["finding_type"] for f in ghost] == ["script-installation"]
    assert len(s.asset_findings(aid, {})) == 2  # no kind -> everything


def test_vulnerabilities_ecosystem_and_asset_type_filters(empty_store):
    s = empty_store
    s.ingest(REPO_PAYLOAD)
    assert len(s.list_vulnerabilities({"ecosystem": ["npm"]})) == 1
    assert len(s.list_vulnerabilities({"ecosystem": ["pypi"]})) == 0
    assert len(s.list_vulnerabilities({"asset_type": ["repository"]})) == 1
    assert len(s.list_vulnerabilities({"asset_type": ["container_image"]})) == 0


def test_assets_provider_and_vulnerable_filters(empty_store):
    s = empty_store
    s.ingest(REPO_PAYLOAD)
    assert len(s.list_assets({"provider": ["github"]})) == 1
    assert len(s.list_assets({"provider": ["gitlab"]})) == 0
    assert len(s.list_assets({"vulnerable": ["true"]})) == 1  # repo has a CVE


def test_assets_vulnerable_filter_paginated_count(empty_store):
    s = empty_store
    s.ingest(REPO_PAYLOAD)
    page = s.list_assets({"vulnerable": ["true"], "limit": ["10"]})
    assert page["total"] == 1 and len(page["items"]) == 1
