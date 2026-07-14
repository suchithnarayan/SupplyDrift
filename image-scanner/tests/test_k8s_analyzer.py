from k8s_cartographer.analyzer import assess_shadow, normalize_workloads
from k8s_cartographer.models import Workload


def _wl(**kwargs) -> Workload:
    base = dict(cluster="c", namespace="default", kind="Deployment", name="x")
    base.update(kwargs)
    return Workload(**base)


def test_helm_managed_is_not_shadow():
    wl = _wl(labels={"app.kubernetes.io/managed-by": "Helm"}, managers=["helm"])
    verdict = assess_shadow(wl)
    assert verdict.is_shadow is False
    assert any("manager:helm" in p or "managed-by:helm" in p for p in verdict.provenance)


def test_argocd_managed_is_not_shadow():
    wl = _wl(labels={"argocd.argoproj.io/instance": "web"}, managers=["argocd-application-controller"])
    assert assess_shadow(wl).is_shadow is False


def test_kubectl_apply_is_shadow_high():
    wl = _wl(
        kind="CronJob",
        managers=["kubectl-client-side-apply"],
        annotations={"kubectl.kubernetes.io/last-applied-configuration": "{}"},
    )
    verdict = assess_shadow(wl)
    assert verdict.is_shadow is True
    assert verdict.confidence == "high"


def test_bare_pod_is_shadow():
    wl = _wl(kind="Pod", managers=[])
    verdict = assess_shadow(wl)
    assert verdict.is_shadow is True
    assert verdict.confidence == "high"


def test_no_metadata_is_shadow_medium():
    wl = _wl(managers=[])
    verdict = assess_shadow(wl)
    assert verdict.is_shadow is True
    assert verdict.confidence == "medium"


def test_owned_children_skipped_by_default():
    resources = [
        {
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": "rs",
                "namespace": "default",
                "ownerReferences": [{"kind": "Deployment", "name": "d"}],
            },
            "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "nginx"}]}}},
        }
    ]
    assert normalize_workloads(resources, "c") == []
    assert len(normalize_workloads(resources, "c", include_owned=True)) == 1
