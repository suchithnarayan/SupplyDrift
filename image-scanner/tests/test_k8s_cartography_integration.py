"""A kubernetes/eks source must publish cluster topology (clusters + workloads)
AND have its image SBOMs land on the SAME container_image assets the workloads
point at — not just bare container images.
"""
from pathlib import Path

from conftest import FakeExtractor, service_cfg

import image_scanner.pipeline as pipeline
from image_scanner.config import parse_config
from image_scanner.connectors.kubernetes import KubernetesConnector
from image_scanner.core.scanner import provider_for

K8S_DUMP = Path(__file__).parent / "fixtures" / "cluster-dump.json"


def _connector():
    src = service_cfg("prod-eks", "kubernetes",
                      {"from_json": str(K8S_DUMP), "cluster_name": "prod-eks-1"})
    return KubernetesConnector(src)


def test_cartography_emits_cluster_workload_and_relationships():
    conn = _connector()
    list(conn.discover_images())  # cartography is captured during discovery
    payloads = conn.cartography_payloads()
    assert len(payloads) == 1
    p = payloads[0]
    types = {a["asset_type"] for a in p["assets"]}
    assert {"k8s_cluster", "k8s_workload", "container_image"} <= types
    rels = {r["relationship_type"] for r in p["relationships"]}
    assert {"belongs_to", "runs_in"} <= rels
    cluster = next(a for a in p["assets"] if a["asset_type"] == "k8s_cluster")
    assert cluster["external_id"] == "prod-eks-1"


def test_cartography_image_identity_matches_sbom_pipeline():
    conn = _connector()
    targets = list(conn.discover_images())
    payloads = conn.cartography_payloads()
    carto_ids = {
        (a["provider"], a["external_id"])
        for p in payloads for a in p["assets"] if a["asset_type"] == "container_image"
    }
    # Every discovered image's (provider, dedup_key) — exactly what the SBOM push
    # uses for its container_image external_id — must appear as a topology image
    # asset, so the platform merges them into ONE asset (same type+provider+id).
    assert targets
    for t in targets:
        assert (provider_for(t), t.dedup_key) in carto_ids


def _config(push: bool):
    return parse_config({
        "version": 2,
        "platform": {"url": "http://127.0.0.1:9", "push": push},
        "scanner": {"extractor": "syft", "concurrency": 1},
        "services": [{
            "name": "prod-eks",
            "type": "kubernetes",
            "connection": {"from_json": str(K8S_DUMP), "cluster_name": "prod-eks-1"},
            "discovery": {"object_kinds": ["CronJob"]},
        }],
    })


def test_pipeline_pushes_topology_and_sbom_with_matching_identity(monkeypatch):
    monkeypatch.setattr(pipeline, "build_extractor", lambda scanner: FakeExtractor())
    img_pushes: list = []
    monkeypatch.setattr(pipeline, "push_image",
                        lambda url, payload, **k: img_pushes.append((url, payload)))
    carto_pushes: list = []
    import k8s_cartographer.publisher as kpub
    monkeypatch.setattr(kpub, "push_to_platform",
                        lambda url, payload, **k: carto_pushes.append((url, payload)))

    result = pipeline.run(_config(push=True))

    assert result.cartography_pushed == 1 and len(carto_pushes) == 1
    assert img_pushes  # at least one SBOM pushed
    img_ids = {p["assets"][0]["external_id"] for _, p in img_pushes}
    carto_img_ids = {
        a["external_id"]
        for _, p in carto_pushes for a in p["assets"] if a["asset_type"] == "container_image"
    }
    # The SBOM'd image id is also a topology image id -> they merge into one asset.
    assert img_ids and img_ids <= carto_img_ids


def test_cartography_push_uses_runner_auth(monkeypatch):
    import k8s_cartographer.publisher as kpub

    captured = {}

    class Response:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"ok": true}'

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["auth"] = request.get_header("Authorization")
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setenv("SUPPLYDRIFT_RUNNER_TOKEN", "runner-token")
    monkeypatch.setattr(kpub, "urlopen", fake_urlopen)

    result = kpub.push_to_platform("http://platform:8765", {"assets": []}, timeout=7)

    assert result["status"] == 201
    assert captured == {
        "url": "http://platform:8765/api/sync/kubernetes-workloads",
        "auth": "Bearer runner-token",
        "timeout": 7,
    }


def test_no_push_keeps_topology_separate_from_image_payloads(monkeypatch):
    monkeypatch.setattr(pipeline, "build_extractor", lambda scanner: FakeExtractor())
    result = pipeline.run(_config(push=False))
    # image SBOMs stay in .payloads; topology goes to .cartography_payloads
    assert len(result.payloads) == 1
    assert result.payloads[0]["assets"][0]["asset_type"] == "container_image"
    assert len(result.cartography_payloads) == 1
    assert any(a["asset_type"] == "k8s_cluster"
               for a in result.cartography_payloads[0]["assets"])
