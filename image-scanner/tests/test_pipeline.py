from pathlib import Path

from conftest import FakeExtractor

import image_scanner.pipeline as pipeline
from image_scanner.config import parse_config

K8S_DUMP = Path(__file__).parent / "fixtures" / "cluster-dump.json"


def make_config():
    return parse_config(
        {
            "version": 2,
            "platform": {"url": "http://127.0.0.1:9", "push": False},
            "scanner": {"extractor": "syft", "concurrency": 1},
            "services": [
                {
                    "id": "connector-k8s",
                    "name": "prod-eks",
                    "type": "kubernetes",
                    "connection": {"from_json": str(K8S_DUMP), "cluster_name": "prod-eks-1"},
                    "discovery": {"object_kinds": ["CronJob"]},
                }
            ],
        }
    )


def test_pipeline_dry_run_discovers_without_scanning(monkeypatch):
    fake = FakeExtractor()
    monkeypatch.setattr(pipeline, "build_extractor", lambda scanner: fake)
    result = pipeline.run(make_config(), dry_run=True)
    assert result.summary()["discovered"] == 1
    assert fake.calls == []


def test_pipeline_scan_builds_payloads_no_push(monkeypatch):
    fake = FakeExtractor()
    monkeypatch.setattr(pipeline, "build_extractor", lambda scanner: fake)
    result = pipeline.run(make_config(), push=False)
    s = result.summary()
    assert s["discovered"] == 1
    assert s["scanned_ok"] == 1
    assert s["pushed"] == 0
    assert len(result.payloads) == 1
    assert result.payloads[0]["assets"][0]["asset_type"] == "container_image"
    assert len(fake.calls) == 1


def test_pipeline_inventory_only_pushes_discovery_without_scanning(monkeypatch):
    fake = FakeExtractor()
    monkeypatch.setattr(pipeline, "build_extractor", lambda scanner: fake)
    result = pipeline.run(make_config(), push=False, inventory_only=True)
    s = result.summary()
    assert s["discovered"] == 1
    assert s["scanned_ok"] == 0 and len(fake.calls) == 0
    assert result.payloads and result.payloads[0]["discovery_only"] is True
    assert result.payloads[0]["connector"]["id"] == "connector-k8s"
    assert result.cartography_payloads and result.cartography_payloads[0]["discovery_only"] is True
    assert result.cartography_payloads[0]["connector"]["id"] == "connector-k8s"
