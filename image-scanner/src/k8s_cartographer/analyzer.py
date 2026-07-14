"""Turn raw Kubernetes resources into workloads, then into SupplyDrift findings.

Two analyses run over the normalized workloads:

1. **Shadow-deployment detection** - does the workload have any evidence of a
   sanctioned delivery path (GitOps, Helm, an operator/controller)? If not, it
   was almost certainly applied by hand (``kubectl apply`` / ``helm install``
   from a laptop) and is a process-enforcement gap.
2. **Image hygiene** - is every container image digest-pinned, and does it come
   from an approved registry? Mutable tags (``:latest``) and unknown registries
   are classic phantom-dependency vectors.
"""
from __future__ import annotations

import fnmatch
from typing import Any

from .image_ref import digest_from_image_id, parse_image_reference
from .models import Container, Finding, ShadowVerdict, Workload

WORKLOAD_KIND_SET = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "CronJob",
    "Job",
    "ReplicaSet",
    "Pod",
}

# managedFields managers / labels that prove an automated, sanctioned owner.
AUTOMATION_MANAGERS = (
    "argocd",
    "argo-cd",
    "application-controller",
    "flux",
    "kustomize-controller",
    "helm-controller",
    "source-controller",
    "helm",
    "terraform",
    "pulumi",
    "spinnaker",
    "fleet",
    "rancher",
    "operator",
    "kube-controller-manager",
    "cronjob-controller",
    "job-controller",
    "deployment-controller",
    "replicaset-controller",
    "statefulset-controller",
    "daemonset-controller",
)

# managedFields managers that indicate an interactive human client.
INTERACTIVE_MANAGERS = (
    "kubectl-client-side-apply",
    "kubectl-edit",
    "kubectl-create",
    "kubectl-set",
    "kubectl-patch",
    "kubectl-run",
    "kubectl-scale",
    "kubectl-rollout",
    "kubectl-label",
    "kubectl-annotate",
    "kubectl-apply",
    "kubectl-replace",
    "kubectl",
    "k9s",
    "lens",
    "octant",
    "kubectl.exe",
)

GITOPS_ANNOTATION_MARKERS = (
    "argocd.argoproj.io",
    "fluxcd.io",
    "kustomize.toolkit.fluxcd.io",
    "helm.toolkit.fluxcd.io",
    "meta.helm.sh",
)

GITOPS_LABEL_MARKERS = (
    "argocd.argoproj.io/instance",
    "kustomize.toolkit.fluxcd.io/name",
    "helm.toolkit.fluxcd.io/name",
)

MANAGED_BY_VALUES = {"helm", "flux", "argocd", "kustomize", "terraform", "pulumi", "spinnaker"}

_CONFIDENCE_TO_SEVERITY = {"high": "critical", "medium": "high", "low": "medium"}


def _pod_spec_for_kind(resource: dict[str, Any]) -> dict[str, Any]:
    spec = resource.get("spec") or {}
    kind = resource.get("kind", "")
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (
            spec.get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
        )
    # Deployment / StatefulSet / DaemonSet / ReplicaSet / Job
    return spec.get("template", {}).get("spec", {})


def _runtime_digests(resource: dict[str, Any]) -> dict[str, str]:
    """Map container name -> resolved digest from a Pod's containerStatuses."""
    digests: dict[str, str] = {}
    if resource.get("kind") != "Pod":
        return digests
    status = resource.get("status") or {}
    for group in ("containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"):
        for entry in status.get(group, []) or []:
            digest = digest_from_image_id(entry.get("imageID", ""))
            if entry.get("name") and digest:
                digests[entry["name"]] = digest
    return digests


def _containers(pod_spec: dict[str, Any], runtime: dict[str, str]) -> list[Container]:
    out: list[Container] = []
    for group, kind in (
        ("containers", "container"),
        ("initContainers", "init"),
        ("ephemeralContainers", "ephemeral"),
    ):
        for c in pod_spec.get(group, []) or []:
            name = c.get("name", "")
            image = parse_image_reference(c.get("image", ""))
            resolved = runtime.get(name, "")
            # Promote a runtime-resolved digest onto an otherwise tag-only ref.
            if resolved and not image.digest:
                image.digest = resolved
            out.append(Container(name=name, image=image, kind=kind, resolved_digest=resolved))
    return out


def _managers(resource: dict[str, Any]) -> list[str]:
    fields = resource.get("metadata", {}).get("managedFields") or []
    managers: list[str] = []
    for entry in fields:
        manager = entry.get("manager")
        if manager:
            managers.append(manager)
    return managers


def _owner_kinds(resource: dict[str, Any]) -> list[str]:
    owners = resource.get("metadata", {}).get("ownerReferences") or []
    return [o.get("kind", "") for o in owners if o.get("kind")]


def normalize_workloads(
    resources: list[dict[str, Any]],
    cluster_name: str,
    include_owned: bool = False,
) -> list[Workload]:
    """Convert raw resources into Workload records.

    By default only *root* workloads (no controller ownerReferences) are kept so
    the inventory reflects logical workloads instead of every churned ReplicaSet
    and Pod. ``include_owned=True`` keeps the full tree.
    """
    workloads: list[Workload] = []
    for resource in resources:
        kind = resource.get("kind", "")
        if kind not in WORKLOAD_KIND_SET:
            continue
        meta = resource.get("metadata") or {}
        owner_kinds = _owner_kinds(resource)
        owned_by_workload = any(k in WORKLOAD_KIND_SET for k in owner_kinds)
        if owned_by_workload and not include_owned:
            continue

        pod_spec = _pod_spec_for_kind(resource)
        runtime = _runtime_digests(resource)
        containers = _containers(pod_spec, runtime)
        if not containers:
            continue

        spec = resource.get("spec") or {}
        workloads.append(
            Workload(
                cluster=cluster_name,
                namespace=meta.get("namespace", "default"),
                kind=kind,
                name=meta.get("name", ""),
                uid=meta.get("uid", ""),
                service_account=pod_spec.get("serviceAccountName", pod_spec.get("serviceAccount", "")),
                node_name=pod_spec.get("nodeName", ""),
                containers=containers,
                labels=meta.get("labels") or {},
                annotations=meta.get("annotations") or {},
                managers=_managers(resource),
                owner_kinds=owner_kinds,
                replicas=spec.get("replicas") if isinstance(spec.get("replicas"), int) else None,
                raw_kind_path=f"{resource.get('apiVersion', '')} {kind}".strip(),
            )
        )
    return workloads


def _classify_managers(managers: list[str]) -> tuple[list[str], list[str]]:
    automation: list[str] = []
    interactive: list[str] = []
    for manager in managers:
        low = manager.lower()
        if any(token in low for token in AUTOMATION_MANAGERS):
            automation.append(manager)
        elif any(low == token or low.startswith(token) for token in INTERACTIVE_MANAGERS):
            interactive.append(manager)
    return automation, interactive


def _gitops_provenance(workload: Workload) -> list[str]:
    provenance: list[str] = []
    for key in workload.annotations:
        if any(marker in key for marker in GITOPS_ANNOTATION_MARKERS):
            provenance.append(f"annotation:{key}")
    for key in workload.labels:
        if key in GITOPS_LABEL_MARKERS:
            provenance.append(f"label:{key}")
    managed_by = (workload.labels.get("app.kubernetes.io/managed-by") or "").lower()
    if managed_by in MANAGED_BY_VALUES:
        provenance.append(f"managed-by:{managed_by}")
    return provenance


def assess_shadow(workload: Workload) -> ShadowVerdict:
    """Decide whether a workload bypassed the sanctioned delivery path."""
    provenance = _gitops_provenance(workload)
    automation, interactive = _classify_managers(workload.managers)
    if automation:
        provenance.append(f"manager:{automation[0]}")

    if provenance:
        return ShadowVerdict(is_shadow=False, confidence="low", provenance=provenance)

    reasons: list[str] = []
    has_last_applied = "kubectl.kubernetes.io/last-applied-configuration" in workload.annotations
    bare_pod = workload.kind == "Pod" and not workload.owner_kinds

    if interactive:
        confidence = "high"
        reasons.append(f"Last modified by interactive client '{interactive[0]}'")
    elif bare_pod:
        confidence = "high"
        reasons.append("Bare Pod with no controller owner (likely 'kubectl run' / 'kubectl apply')")
    elif has_last_applied:
        confidence = "medium"
        reasons.append("Applied via kubectl with no GitOps, Helm, or operator provenance")
    elif not workload.managers:
        confidence = "medium"
        reasons.append("No provenance metadata: no GitOps label, Helm release, or controller manager")
    else:
        confidence = "medium"
        reasons.append("No sanctioned delivery path found in metadata")

    if has_last_applied and "Applied via kubectl" not in " ".join(reasons):
        reasons.append("kubectl last-applied-configuration present")

    return ShadowVerdict(is_shadow=True, confidence=confidence, reasons=reasons, provenance=provenance)


def _registry_trusted(registry: str, trusted: list[str]) -> bool:
    return any(fnmatch.fnmatch(registry, pattern) for pattern in trusted)


def image_findings(
    workload: Workload,
    container: Container,
    asset_ref: str,
    trusted_registries: list[str],
) -> list[Finding]:
    findings: list[Finding] = []
    image = container.image
    evidence_base = {
        "image": image.reference,
        "container": container.name,
        "namespace": workload.namespace,
        "workload": f"{workload.kind}/{workload.name}",
    }

    if not image.pinned:
        if image.mutable_tag:
            findings.append(
                Finding(
                    asset_ref=asset_ref,
                    finding_type="unpinned_image",
                    severity="high",
                    title="Runtime workload uses a mutable image tag",
                    description=(
                        f"{image.reference} uses tag ':{image.tag}', which can resolve to "
                        "different content over time and bypasses image SBOM/CVE history."
                    ),
                    fix_recommendation="Pin the image to an immutable digest (image@sha256:...).",
                    evidence={**evidence_base, "tag": image.tag},
                )
            )
        else:
            findings.append(
                Finding(
                    asset_ref=asset_ref,
                    finding_type="unpinned_image",
                    severity="medium",
                    title="Runtime workload image is not digest-pinned",
                    description=(
                        f"{image.reference} is tag-pinned but not digest-pinned; the same tag "
                        "may be repushed with different content."
                    ),
                    fix_recommendation="Reference the image by digest (image@sha256:...).",
                    evidence={**evidence_base, "tag": image.tag},
                )
            )

    if trusted_registries and not _registry_trusted(image.registry, trusted_registries):
        findings.append(
            Finding(
                asset_ref=asset_ref,
                finding_type="untrusted_registry",
                severity="high",
                title="Runtime workload pulls from an unapproved registry",
                description=(
                    f"Registry '{image.registry}' is not in the approved registry allowlist."
                ),
                fix_recommendation="Mirror the image into an approved registry and update the reference.",
                evidence={**evidence_base, "registry": image.registry},
            )
        )
    return findings


def shadow_finding(workload: Workload, verdict: ShadowVerdict, asset_ref: str) -> Finding:
    severity = _CONFIDENCE_TO_SEVERITY.get(verdict.confidence, "high")
    return Finding(
        asset_ref=asset_ref,
        finding_type="shadow_deployment",
        severity=severity,
        title="Workload has no approved delivery path",
        description=(
            f"{workload.kind} '{workload.name}' in namespace '{workload.namespace}' is running "
            "but shows no GitOps, Helm, or operator provenance — it was likely applied directly "
            "to the cluster, bypassing admission-time SCA and audit. "
            + "; ".join(verdict.reasons)
        ),
        fix_recommendation="Move the workload into the approved CI/CD or GitOps pipeline, or remove it.",
        evidence={
            "cluster": workload.cluster,
            "namespace": workload.namespace,
            "kind": workload.kind,
            "name": workload.name,
            "confidence": verdict.confidence,
            "reasons": verdict.reasons,
            "managers": workload.managers,
            "service_account": workload.service_account,
        },
    )
