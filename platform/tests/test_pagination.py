"""Pagination contract: {items, total, limit, offset} envelope + backward compat."""
from __future__ import annotations

import pytest


def _seed(store, n=12):
    """Ingest n container-image assets so we have something to page through."""
    for i in range(n):
        store.ingest({
            "scan_metadata": {"started_at": "2026-06-09T10:00:00+00:00", "component_count": 1},
            "assets": [{"ref": "img", "asset_type": "container_image", "provider": "docker_hub",
                        "external_id": f"img:test{i}@sha256:{i:02d}", "display_name": f"test{i}:latest",
                        "details": {"registry_url": "docker.io", "repository": f"test{i}", "tag": "latest"}}],
            "components": [{"ref": f"pkg:npm/p{i}@1", "name": f"p{i}", "version": "1",
                            "ecosystem": "npm", "package_manager": "npm", "purl": f"pkg:npm/p{i}@1"}],
            "component_usages": [{"asset_ref": "img", "component_ref": f"pkg:npm/p{i}@1", "source": "image_scan"}],
        })


def test_list_assets_backward_compatible_list(empty_store):
    _seed(empty_store, 5)
    rows = empty_store.list_assets({})  # no pagination params -> plain list
    assert isinstance(rows, list) and len(rows) == 5


def test_list_assets_paginated_envelope(empty_store):
    _seed(empty_store, 12)
    page1 = empty_store.list_assets({"limit": ["5"], "offset": ["0"]})
    assert set(page1) == {"items", "total", "limit", "offset"}
    assert page1["total"] == 12 and page1["limit"] == 5 and len(page1["items"]) == 5
    page3 = empty_store.list_assets({"limit": ["5"], "offset": ["10"]})
    assert page3["total"] == 12 and len(page3["items"]) == 2  # remainder
    # page param maps to offset
    assert empty_store.list_assets({"limit": ["5"], "page": ["2"]})["offset"] == 5


def test_limit_clamped(empty_store):
    _seed(empty_store, 3)
    assert empty_store.list_assets({"limit": ["99999"]})["limit"] == 200  # max
    assert empty_store.list_assets({"limit": ["0"]})["limit"] == 1        # min


def test_paginated_total_respects_filter(empty_store):
    _seed(empty_store, 6)
    res = empty_store.list_assets({"asset_type": ["container_image"], "limit": ["2"]})
    assert res["total"] == 6 and len(res["items"]) == 2
    res2 = empty_store.list_assets({"asset_type": ["endpoint"], "limit": ["2"]})
    assert res2["total"] == 0 and res2["items"] == []


@pytest.mark.parametrize("method", ["sbom_packages", "list_components", "list_vulnerabilities"])
def test_other_lists_paginate(empty_store, method):
    _seed(empty_store, 8)
    res = getattr(empty_store, method)({"limit": ["3"]})
    assert set(res) == {"items", "total", "limit", "offset"}
    assert res["limit"] == 3 and len(res["items"]) <= 3
    # backward compat: no params -> list
    assert isinstance(getattr(empty_store, method)({}), list)
