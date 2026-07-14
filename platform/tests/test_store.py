"""Golden Store-level contract tests (current behavior)."""
from __future__ import annotations


def test_summary_shape(store):
    s = store.summary()
    assert set(s) >= {"assets", "components", "findings", "connectors", "scan", "vulnerability_status"}
    assert set(s["assets"]) >= {"total", "by_type", "stale"}
    assert isinstance(s["assets"]["by_type"], dict)
    assert s["assets"]["total"] >= 1
    assert set(s["components"]) >= {"total", "top"}
    assert set(s["findings"]) >= {"by_severity", "latest"}
    assert set(s["scan"]) >= {"total", "scanned", "pending", "failed"}


def test_graph_limit_is_clamped_and_robust(store):
    # Unbounded/malformed limits must not crash or return an unbounded set (SD-08).
    assert isinstance(store.graph({"limit": ["999999999"]})["nodes"], list)  # huge -> clamped
    assert isinstance(store.graph({"limit": ["abc"]})["nodes"], list)         # non-numeric -> default, no crash
    assert isinstance(store.graph({"limit": ["0"]})["nodes"], list)           # zero -> floored to >=1
    assert isinstance(store.graph({})["nodes"], list)


def test_scan_status_on_ingest(empty_store):
    # An SBOM push marks the asset 'scanned' with last_scanned_at.
    empty_store.ingest({
        "scan_metadata": {"started_at": "2026-06-09T10:00:00+00:00"},
        "assets": [{"ref": "img", "asset_type": "container_image", "provider": "docker_hub",
                    "external_id": "img:x@sha256:aa", "display_name": "x:latest", "details": {"repository": "x"}}],
        "components": [{"ref": "pkg:npm/a@1", "name": "a", "version": "1", "ecosystem": "npm", "purl": "pkg:npm/a@1"}],
        "component_usages": [{"asset_ref": "img", "component_ref": "pkg:npm/a@1", "source": "image_scan"}],
    })
    a = empty_store.list_assets({})[0]
    assert a["scan_status"] == "scanned" and a["last_scanned_at"]
    s = empty_store.summary()["scan"]
    assert s["total"] == 1 and s["scanned"] == 1 and s["pending"] == 0


def test_discovery_only_is_pending(empty_store):
    empty_store.ingest({
        "discovery_only": True,
        "scan_metadata": {"started_at": "2026-06-09T10:00:00+00:00"},
        "assets": [{"ref": "img", "asset_type": "container_image", "provider": "docker_hub",
                    "external_id": "img:stub@latest", "display_name": "stub:latest", "details": {"repository": "stub"}}],
    })
    a = empty_store.list_assets({"scan_status": ["discovered"]})
    assert a and a[0]["scan_status"] == "discovered" and not a[0]["last_scanned_at"]
    assert empty_store.summary()["scan"]["pending"] == 1


def test_sync_payload_uses_existing_connector_id(empty_store):
    c = empty_store.save_connector({
        "name": "DockerHub Source",
        "source_type": "dockerhub",
        "connection": {"images": ["alpine:3.18"]},
    })
    empty_store.sync_source_payload("container-images", {
        "connector": {"id": c["id"], "name": "DockerHub Source", "connector_type": "registry_scanner"},
        "source_name": "DockerHub Source",
        "assets": [{
            "ref": "img",
            "asset_type": "container_image",
            "provider": "docker_hub",
            "external_id": "registry-1.docker.io/library/alpine:3.18",
            "display_name": "library/alpine:3.18",
            "details": {"registry_url": "registry-1.docker.io", "repository": "library/alpine", "tag": "3.18"},
        }],
    })
    asset = empty_store.list_assets({})[0]
    assert asset["connector_id"] == c["id"]
    connectors = empty_store.list_connectors()
    assert len(connectors) == 1
    assert connectors[0]["name"] == "DockerHub Source" and connectors[0]["asset_count"] == 1


def test_relationships_backfill_k8s_workload_detail_links(empty_store):
    empty_store.ingest({
        "assets": [
            {"ref": "cluster", "asset_type": "k8s_cluster", "provider": "kubernetes",
             "external_id": "docker-desktop", "display_name": "docker-desktop"},
            {"ref": "workload", "asset_type": "k8s_workload", "provider": "kubernetes",
             "external_id": "docker-desktop/default/Deployment/web/app", "display_name": "default/web:app",
             "details": {"cluster_name": "docker-desktop", "namespace": "default",
                         "workload_kind": "Deployment", "workload_name": "web",
                         "container_name": "app", "image_reference": "docker.io/library/nginx:1.27"}},
            {"ref": "image", "asset_type": "container_image", "provider": "docker_hub",
             "external_id": "docker.io/library/nginx:1.27", "display_name": "library/nginx:1.27",
             "details": {"registry_url": "docker.io", "repository": "library/nginx", "tag": "1.27"}},
        ],
        "relationships": [
            {"source_ref": "workload", "relationship_type": "belongs_to", "target_ref": "cluster"},
            {"source_ref": "image", "relationship_type": "runs_in", "target_ref": "workload"},
        ],
    })
    assets = {a["display_name"]: a["id"] for a in empty_store.list_assets({})}
    workload = empty_store.get_asset(assets["default/web:app"])
    assert workload["details"]["cluster_asset_id"] == assets["docker-desktop"]
    assert workload["details"]["image_asset_id"] == assets["library/nginx:1.27"]


def test_list_assets(store):
    rows = store.list_assets({})
    assert isinstance(rows, list) and rows
    a = rows[0]
    assert {"id", "asset_type", "display_name", "component_count", "finding_count"} <= set(a)


def test_list_assets_filter_by_type(store):
    rows = store.list_assets({"asset_type": ["container_image"]})
    assert all(a["asset_type"] == "container_image" for a in rows)


def test_get_asset(store):
    first = store.list_assets({})[0]
    detail = store.get_asset(first["id"])
    assert detail is not None
    # Slim detail: counts + relationships; big lists fetched via sub-endpoints.
    assert {"id", "details", "relationships", "component_count", "finding_count"} <= set(detail)
    assert store.get_asset("does-not-exist") is None


def test_asset_components_and_findings_paginated(empty_store):
    empty_store.ingest({
        "scan_metadata": {"started_at": "2026-06-09T10:00:00+00:00"},
        "assets": [{"ref": "img", "asset_type": "container_image", "provider": "docker_hub",
                    "external_id": "img:y@sha256:bb", "display_name": "y:latest", "details": {"repository": "y"}}],
        "components": [{"ref": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20",
                        "ecosystem": "npm", "package_manager": "npm", "purl": "pkg:npm/lodash@4.17.20"}],
        "component_usages": [{"asset_ref": "img", "component_ref": "pkg:npm/lodash@4.17.20",
                              "source": "image_scan", "evidence_path": "/app/package-lock.json"}],
        "findings": [{"asset_ref": "img", "component_ref": "pkg:npm/lodash@4.17.20", "finding_type": "cve",
                      "severity": "high", "title": "CVE-2021-23337", "fix_recommendation": "Upgrade lodash to 4.17.21"}],
    })
    aid = empty_store.list_assets({})[0]["id"]

    comps = empty_store.asset_components(aid, {"limit": ["10"]})
    assert set(comps) == {"items", "total", "limit", "offset"}
    c = comps["items"][0]
    assert c["name"] == "lodash" and c["finding_count"] == 1   # per-component count is correct

    finds = empty_store.asset_findings(aid, {"limit": ["10"]})
    f = finds["items"][0]
    assert f["title"] == "CVE-2021-23337"
    assert f["component_name"] == "lodash" and f["component_version"] == "4.17.20"  # package shown
    assert f["fix_recommendation"] == "Upgrade lodash to 4.17.21"                    # upgrade shown
    # backward-compat (no params -> list)
    assert isinstance(empty_store.asset_findings(aid, {}), list)


def test_asset_component_count_matches_paginated_occurrences(empty_store):
    empty_store.ingest({
        "assets": [{
            "ref": "repo", "asset_type": "repository", "provider": "github",
            "external_id": "github.com/acme/repeated", "display_name": "acme/repeated",
        }],
        "components": [{
            "ref": "pkg:npm/lodash@4.17.21", "name": "lodash", "version": "4.17.21",
            "ecosystem": "npm", "package_manager": "npm", "purl": "pkg:npm/lodash@4.17.21",
        }],
        "component_usages": [
            {"asset_ref": "repo", "component_ref": "pkg:npm/lodash@4.17.21",
             "source": "repo_sbom", "evidence_path": "/app-a/package-lock.json"},
            {"asset_ref": "repo", "component_ref": "pkg:npm/lodash@4.17.21",
             "source": "repo_sbom", "evidence_path": "/app-b/package-lock.json"},
        ],
    })
    listed = empty_store.list_assets({})[0]
    detail = empty_store.get_asset(listed["id"])
    components = empty_store.asset_components(listed["id"], {"limit": ["10"]})

    assert listed["component_count"] == 2
    assert detail["component_count"] == 2
    assert components["total"] == 2 and len(components["items"]) == 2


def test_list_findings(store):
    rows = store.list_findings({})
    assert isinstance(rows, list)
    if rows:
        assert {"id", "finding_type", "severity", "title"} <= set(rows[0])


def test_list_vulnerability_status(store):
    rows = store.list_vulnerability_status({})
    assert isinstance(rows, list)
    if rows:
        assert {"name", "vulnerability_status", "max_severity"} <= set(rows[0])


def test_sbom_packages_and_versions(store):
    pkgs = store.sbom_packages({})
    assert isinstance(pkgs, list)
    if pkgs:
        assert {"name", "ecosystem"} <= set(pkgs[0])
        versions = store.sbom_versions({"name": [pkgs[0]["name"]]})
        assert isinstance(versions, list)


def test_list_connectors(store):
    rows = store.list_connectors()
    assert isinstance(rows, list)


def test_scanner_config(store):
    cfg = store.scanner_config()
    assert {"version", "platform", "registries", "services", "github"} <= set(cfg)
    assert isinstance(cfg["registries"], list)


def test_graph(store):
    g = store.graph({})
    assert {"nodes", "edges"} <= set(g)


def test_sync_endpoint_sbom_batch(empty_store):
    batch = {
        "scan_id": "s1", "scanned_at": "2026-06-09T10:00:00+00:00",
        "endpoint": {"id": "ep1", "hostname": "lap", "os": "Linux", "arch": "x86_64"},
        "scanner": {"name": "syft", "version": "1.0"},
        "packages": [{"name": "lodash", "version": "4.17.20", "type": "npm",
                      "purl": "pkg:npm/lodash@4.17.20", "locations": ["/a/package-lock.json"]}],
    }
    res = empty_store.sync_source_payload("endpoints", batch)
    assert res["summary"]["assets"] == 1
    assert empty_store.list_assets({"asset_type": ["endpoint"]})


def test_sync_endpoint_vuln_batch_creates_cve_finding(empty_store):
    ep = {"id": "ep2", "hostname": "lap2", "os": "Linux", "arch": "x86_64"}
    empty_store.sync_source_payload("endpoints", {
        "scan_id": "s2", "scanned_at": "2026-06-09T10:00:00+00:00", "endpoint": ep, "scanner": {"name": "syft"},
        "packages": [{"name": "lodash", "version": "4.17.20", "type": "npm", "purl": "pkg:npm/lodash@4.17.20"}],
    })
    empty_store.sync_source_payload("endpoints", {
        "scan_id": "s2", "scanned_at": "2026-06-09T10:00:05+00:00", "endpoint": ep, "scanner": {"name": "grype"},
        "vulnerabilities": [{"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20",
                             "id": "CVE-2021-23337", "severity": "high", "fix": "4.17.21"}],
    })
    cves = [f for f in empty_store.list_findings({"finding_type": ["cve"]}) if f["title"] == "CVE-2021-23337"]
    assert cves and cves[0]["severity"] == "high"


def test_list_vulnerabilities_returns_cve_findings(empty_store):
    ep = {"id": "ep4", "hostname": "h4", "os": "Linux"}
    empty_store.sync_source_payload("endpoints", {
        "scan_id": "v1", "scanned_at": "2026-06-09T10:00:00+00:00", "endpoint": ep, "scanner": {"name": "syft"},
        "packages": [{"name": "lodash", "version": "4.17.20", "type": "npm", "purl": "pkg:npm/lodash@4.17.20"}],
    })
    empty_store.sync_source_payload("endpoints", {
        "scan_id": "v1", "scanned_at": "2026-06-09T10:00:05+00:00", "endpoint": ep, "scanner": {"name": "grype"},
        "vulnerabilities": [{"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20",
                             "id": "CVE-2021-23337", "severity": "critical", "fix": "4.17.21"}],
    })
    vulns = empty_store.list_vulnerabilities({})
    assert vulns and vulns[0]["finding_type"] == "cve"
    assert {"title", "severity", "component_name", "component_version", "asset_name", "fix_recommendation"} <= set(vulns[0])
    assert empty_store.list_vulnerabilities({"severity": ["critical"]})
    assert empty_store.list_vulnerabilities({"search": ["lodash"]})


def test_sync_batch_without_scanned_at_does_not_crash(empty_store):
    # A sparse batch (no scanned_at) must not 500 on scan_jobs.started_at.
    res = empty_store.sync_source_payload("endpoints", {
        "endpoint": {"id": "ep3", "hostname": "h3", "os": "Linux"},
        "scanner": {"name": "syft"},
        "packages": [{"name": "x", "version": "1", "type": "npm", "purl": "pkg:npm/x@1"}],
    })
    assert res["summary"]["assets"] == 1
