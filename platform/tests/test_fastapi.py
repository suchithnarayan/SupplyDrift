"""Parity tests: the FastAPI app must satisfy the SAME contract as the stdlib
server (the Phase-0 golden tests), proving the migration is behavior-preserving.
"""
from __future__ import annotations

import gzip
import json

import pytest


def test_summary(fastapi_client):
    client, _ = fastapi_client
    r = client.get("/api/summary")
    assert r.status_code == 200
    assert {"assets", "components", "findings", "scan", "vulnerability_status"} <= set(r.json())


def test_list_assets(fastapi_client):
    client, _ = fastapi_client
    r = client.get("/api/assets")
    assert r.status_code == 200 and isinstance(r.json(), list)


def test_assets_paginated_envelope(fastapi_client):
    client, _ = fastapi_client
    r = client.get("/api/assets?limit=2&offset=0")
    assert r.status_code == 200
    assert set(r.json()) == {"items", "total", "limit", "offset"}


def test_asset_detail_sub_endpoints_and_404(fastapi_client):
    client, _ = fastapi_client
    assets = client.get("/api/assets").json()
    aid = assets[0]["id"]
    body = client.get(f"/api/assets/{aid}").json()
    assert {"id", "component_count", "finding_count", "relationships"} <= set(body)
    assert client.get(f"/api/assets/{aid}/components").status_code == 200
    assert client.get(f"/api/assets/{aid}/findings").status_code == 200
    assert client.get("/api/assets/nope").status_code == 404


def test_findings_vulnerabilities_sbom(fastapi_client):
    client, _ = fastapi_client
    assert client.get("/api/findings").status_code == 200
    assert client.get("/api/vulnerabilities").status_code == 200
    assert client.get("/api/sbom/packages").status_code == 200


def test_components_graph_connectors_config(fastapi_client):
    client, _ = fastapi_client
    assert client.get("/api/components").status_code == 200
    assert client.get("/api/graph").status_code == 200
    assert client.get("/api/connectors").status_code == 200
    cfg = client.get("/api/scanner/config")
    assert cfg.status_code == 200 and {"registries", "services", "github"} <= set(cfg.json())


def test_osv_check_removed(fastapi_client):
    client, _ = fastapi_client
    assert client.post("/api/vulnerabilities/check", json={"limit": 10}).status_code == 404


def test_gzip_bomb_and_oversize_body_rejected(fastapi_client, monkeypatch):
    import gzip as _gz

    import server
    client, _ = fastapi_client
    # Tiny ceilings so the test stays fast.
    monkeypatch.setattr(server, "_MAX_DECOMPRESSED", 1024)
    monkeypatch.setattr(server, "_MAX_BODY", 4096)

    bomb = _gz.compress(b"A" * (64 * 1024))  # decompresses to 64KB > 1KB ceiling
    r = client.post("/api/sync/container-images", content=bomb,
                    headers={"Content-Type": "application/json", "Content-Encoding": "gzip"})
    assert r.status_code == 413

    big = b"x" * (8 * 1024)  # 8KB > 4KB raw ceiling
    r = client.post("/api/sync/container-images", content=big,
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_demo_routes_gated_by_flag(fastapi_client, monkeypatch):
    client, _ = fastapi_client
    monkeypatch.delenv("SUPPLYDRIFT_DEMO", raising=False)
    assert client.post("/api/demo/reset").status_code == 404
    assert client.post("/api/demo/load").status_code == 404
    monkeypatch.setenv("SUPPLYDRIFT_DEMO", "true")
    assert client.post("/api/demo/load").status_code == 200
    assert client.post("/api/demo/reset").status_code == 200


def test_connector_crud(fastapi_client):
    client, _ = fastapi_client
    created = client.post("/api/connectors", json={
        "name": "test-reg", "source_type": "dockerhub", "connection": {"namespaces": ["acme"]},
    })
    assert created.status_code == 201 and created.json()["config"]["kind"] == "registry"
    cid = created.json()["id"]
    assert client.delete(f"/api/connectors/{cid}").status_code == 200


def test_sync_container_image_gzip(fastapi_client):
    client, store = fastapi_client
    payload = {
        "source_name": "t", "scan_metadata": {"component_count": 1, "vulnerability_count": 0},
        "assets": [{"ref": "img", "asset_type": "container_image", "provider": "docker_hub",
                    "external_id": "img:fa@sha256:cc", "display_name": "fa:latest",
                    "details": {"registry_url": "docker.io", "repository": "fa", "tag": "latest", "digest": "sha256:cc"}}],
        "components": [{"ref": "pkg:deb/z@1", "name": "z", "version": "1", "ecosystem": "deb",
                        "package_manager": "deb", "purl": "pkg:deb/z@1"}],
        "component_usages": [{"asset_ref": "img", "component_ref": "pkg:deb/z@1", "source": "image_scan"}],
        "findings": [],
    }
    r = client.post(
        "/api/sync/container-images",
        content=gzip.compress(json.dumps(payload).encode()),
        headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
    )
    assert r.status_code == 201
    assert any(a["external_id"] == "img:fa@sha256:cc" for a in store.list_assets({"asset_type": ["container_image"]}))


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"content": b"", "headers": {"Content-Type": "application/json"}},
        {"json": {}},
        {"json": []},
        {"json": {"components": [], "findings": []}},
        {"json": {"assets": []}},
    ],
    ids=["empty-body", "empty-object", "non-object", "missing-assets", "empty-assets"],
)
def test_ingest_rejects_invalid_envelopes_without_persisting(fastapi_client, request_kwargs):
    client, store = fastapi_client
    with store.connect() as conn:
        before = {
            "assets": conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0],
            "scan_jobs": conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0],
        }

    response = client.post("/api/ingest", **request_kwargs)

    assert response.status_code == 422
    with store.connect() as conn:
        after = {
            "assets": conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0],
            "scan_jobs": conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0],
        }
    assert after == before


def test_ingest_accepts_asset_only_payload(fastapi_client):
    client, store = fastapi_client
    payload = {
        "assets": [
            {
                "ref": "asset-only",
                "asset_type": "repository",
                "provider": "github",
                "external_id": "github:acme/asset-only",
                "display_name": "acme/asset-only",
            }
        ],
        "components": [],
        "findings": [],
    }

    response = client.post("/api/ingest", json=payload)

    assert response.status_code == 201
    assert response.json()["summary"] == {
        "assets": 1,
        "components": 0,
        "relationships": 0,
        "findings": 0,
        "raw_sboms": 0,
    }
    assert any(asset["external_id"] == "github:acme/asset-only" for asset in store.list_assets({}))


def test_spa_fallback(fastapi_client):
    client, _ = fastapi_client
    # A non-API route should not 500 (serves index.html if built, else a stub).
    assert client.get("/inventory").status_code == 200
