from pathlib import Path

from conftest import registry_cfg, service_cfg

from image_scanner.auth.index import RegistryAuthIndex
from image_scanner.connectors.kubernetes import KubernetesConnector

K8S_DUMP = Path(__file__).parent / "fixtures" / "cluster-dump.json"


def make_source(discovery=None, **filter_kwargs):
    return service_cfg(
        "prod-eks",
        "kubernetes",
        {"from_json": str(K8S_DUMP), "cluster_name": "prod-eks-1"},
        discovery=discovery,
        **filter_kwargs,
    )


def test_k8s_discovers_root_workload_images():
    conn = KubernetesConnector(make_source())
    repos = {t.repository for t in conn.discover_images()}
    assert "payments-api" in repos
    assert "acme/web" in repos
    assert "acme/web-migrate" in repos  # init container included by default
    assert any(r.endswith("python") or r == "library/python" for r in repos)


def test_k8s_excludes_init_when_disabled():
    conn = KubernetesConnector(make_source(discovery={"include_init_containers": False}))
    repos = {t.repository for t in conn.discover_images()}
    assert "acme/web-migrate" not in repos
    assert "acme/web" in repos


def test_k8s_reuses_registry_index_for_pull_auth(monkeypatch):
    monkeypatch.setenv("GHCR_USER", "robot")
    monkeypatch.setenv("GHCR_TOKEN", "secret")
    index = RegistryAuthIndex.from_registries(
        [registry_cfg("ghcr", "ghcr", {"auth": {"username_env": "GHCR_USER", "token_env": "GHCR_TOKEN"}})]
    )
    conn = KubernetesConnector(make_source(), index=index)
    target = next(t for t in conn.discover_images() if t.registry == "ghcr.io")
    auth = conn.registry_auth_for(target)
    assert auth is not None and auth.username == "robot" and auth.password == "secret"
    rc = target.discovered_via["registry_connection"]
    assert rc["configured"] and rc["source"] == "ghcr" and rc["auth_provider"] == "env"


def test_k8s_object_kind_filter():
    conn = KubernetesConnector(make_source(discovery={"object_kinds": ["CronJob"]}))
    targets = list(conn.discover_images())
    assert {t.discovered_via["workload"] for t in targets} == {"CronJob/data-migration"}


def test_k8s_marks_unconfigured_registry_connection():
    conn = KubernetesConnector(make_source(), index=RegistryAuthIndex())
    target = next(t for t in conn.discover_images() if t.registry == "ghcr.io")
    assert target.discovered_via["registry_connection"]["configured"] is False
