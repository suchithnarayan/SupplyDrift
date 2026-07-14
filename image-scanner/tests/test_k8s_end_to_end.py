from pathlib import Path

from k8s_cartographer.analyzer import normalize_workloads
from k8s_cartographer.collector import collect_from_json_file
from k8s_cartographer.payload import build_payload
from k8s_cartographer.report import summarize

FIXTURE = Path(__file__).parent / "fixtures" / "cluster-dump.json"


def _payload(trusted=None):
    resources = collect_from_json_file(FIXTURE)
    workloads = normalize_workloads(resources, "prod-eks-1")
    return build_payload(workloads, "prod-eks-1", provider="aws", trusted_registries=trusted or [])


def test_root_workloads_only_by_default():
    resources = collect_from_json_file(FIXTURE)
    workloads = normalize_workloads(resources, "prod-eks-1")
    names = sorted(w.name for w in workloads)
    # The Deployment-owned ReplicaSet and Pod are excluded.
    assert names == ["adhoc-backup", "data-migration", "debug-shell", "log-collector", "payments-api", "web"]


def test_shadow_deployments_detected():
    payload = _payload()
    shadow = [f for f in payload["findings"] if f["finding_type"] == "shadow_deployment"]
    shadow_workloads = sorted(f["evidence"]["name"] for f in shadow)
    assert shadow_workloads == ["adhoc-backup", "data-migration", "debug-shell"]
    assert all(f["severity"] == "critical" for f in shadow)


def test_unpinned_images_detected():
    payload = _payload()
    unpinned = [f for f in payload["findings"] if f["finding_type"] == "unpinned_image"]
    high = [f for f in unpinned if f["severity"] == "high"]
    medium = [f for f in unpinned if f["severity"] == "medium"]
    # python:latest is mutable with no runtime digest (high). busybox resolves to
    # a digest via the Pod's containerStatuses, so it is treated as pinned.
    # ghcr web:1.4.2, web-migrate:1.4.2 and internal backup:2.0 are tag-only (medium).
    assert len(high) == 1
    assert len(medium) == 3


def test_digest_pinned_images_have_no_unpinned_finding():
    payload = _payload()
    images = {a["external_id"] for a in payload["assets"] if a["asset_type"] == "container_image"}
    assert any("payments-api@sha256:" in ref for ref in images)
    unpinned_refs = {f["evidence"]["image"] for f in payload["findings"] if f["finding_type"] == "unpinned_image"}
    assert not any("@sha256:" in ref for ref in unpinned_refs)


def test_untrusted_registry_with_allowlist():
    payload = _payload(trusted=["123456789012.dkr.ecr.*", "ghcr.io"])
    untrusted = [f for f in payload["findings"] if f["finding_type"] == "untrusted_registry"]
    registries = sorted({f["evidence"]["registry"] for f in untrusted})
    # docker.io (python, busybox) and registry.internal.acme.com (backup) are not approved.
    assert registries == ["docker.io", "registry.internal.acme.com"]


def test_assets_and_relationships_shape():
    payload = _payload()
    summary = summarize(payload)
    assert summary["assets_by_type"]["k8s_cluster"] == 1
    assert summary["assets_by_type"]["k8s_workload"] >= 6
    assert summary["assets_by_type"]["container_image"] >= 1
    rel_types = {r["relationship_type"] for r in payload["relationships"]}
    assert rel_types == {"belongs_to", "runs_in"}
