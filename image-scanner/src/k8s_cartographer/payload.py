"""Render analyzed workloads into the SupplyDrift sync payload.

Produces the normalized shape the platform's ``/api/sync/kubernetes-workloads``
endpoint accepts: ``assets`` (cluster, workloads, images), ``relationships``
(workload→cluster, image→workload) and ``findings`` (shadow deployments and
image-hygiene issues).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .analyzer import assess_shadow, image_findings, shadow_finding
from .image_ref import ImageRef
from .models import Workload


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def registry_type(registry: str) -> str:
    reg = registry.lower()
    if "amazonaws" in reg or ".ecr." in reg or reg.endswith("ecr.amazonaws.com"):
        return "ecr"
    if "gcr.io" in reg or "pkg.dev" in reg:
        return "gcr"
    if "azurecr.io" in reg:
        return "acr"
    if "ghcr.io" in reg:
        return "ghcr"
    if reg in {"docker.io", "registry-1.docker.io", "index.docker.io"}:
        return "dockerhub"
    if reg.startswith("quay.io"):
        return "quay"
    return "other"


def _image_ref_id(image: ImageRef) -> str:
    return f"img:{image.reference}"


def _image_asset(image: ImageRef, provider: str, environment: str) -> dict[str, Any]:
    return {
        "ref": _image_ref_id(image),
        "asset_type": "container_image",
        "provider": provider,
        "external_id": image.reference,
        "display_name": f"{image.repository}:{image.tag}" if image.tag else image.repository,
        "environment": environment,
        "status": "active",
        "details": {
            "registry_type": registry_type(image.registry),
            "registry_url": image.registry,
            "repository": image.repository,
            "image_name": image.name,
            "tag": image.tag,
            "digest": image.digest,
        },
    }


def _cluster_ref(cluster_name: str) -> str:
    return f"cluster:{cluster_name}"


def build_payload(
    workloads: list[Workload],
    cluster_name: str,
    provider: str = "kubernetes",
    environment: str = "",
    trusted_registries: list[str] | None = None,
    scanner_version: str = "k8s-cartographer-0.1.0",
) -> dict[str, Any]:
    trusted_registries = trusted_registries or []
    assets: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    image_refs_seen: dict[str, ImageRef] = {}

    cluster_ref = _cluster_ref(cluster_name)
    assets.append(
        {
            "ref": cluster_ref,
            "asset_type": "k8s_cluster",
            "provider": provider,
            "external_id": cluster_name,
            "display_name": cluster_name,
            "environment": environment,
            "status": "active",
            "raw_metadata": {"scanner": scanner_version},
        }
    )

    for workload in workloads:
        verdict = assess_shadow(workload)
        first_asset_ref: str | None = None
        for container in workload.containers:
            asset_ref = f"wl:{workload.external_id(container.name)}"
            if first_asset_ref is None:
                first_asset_ref = asset_ref
            image = container.image
            assets.append(
                {
                    "ref": asset_ref,
                    "asset_type": "k8s_workload",
                    "provider": provider,
                    "external_id": workload.external_id(container.name),
                    "display_name": f"{workload.namespace}/{workload.name}:{container.name}",
                    "owner": "unknown" if verdict.is_shadow else "",
                    "environment": environment,
                    "status": "active",
                    "tags": ["shadow-deployment"] if verdict.is_shadow else [],
                    "details": {
                        "cluster_name": workload.cluster,
                        "cloud_provider": provider,
                        "namespace": workload.namespace,
                        "workload_kind": workload.kind,
                        "workload_name": workload.name,
                        "container_name": container.name,
                        "service_account": workload.service_account,
                        "image_reference": image.reference,
                        "image_digest": image.digest,
                        "node_name": workload.node_name,
                    },
                    "raw_metadata": {
                        "container_kind": container.kind,
                        "managers": workload.managers,
                        "owner_kinds": workload.owner_kinds,
                        "provenance": verdict.provenance,
                    },
                }
            )

            relationships.append(
                {"source_ref": asset_ref, "relationship_type": "belongs_to", "target_ref": cluster_ref}
            )

            image_id = _image_ref_id(image)
            if image_id not in image_refs_seen:
                image_refs_seen[image_id] = image
            relationships.append(
                {
                    "source_ref": image_id,
                    "relationship_type": "runs_in",
                    "target_ref": asset_ref,
                    "evidence": {"image_digest": image.digest, "container": container.name},
                }
            )

            for finding in image_findings(workload, container, asset_ref, trusted_registries):
                findings.append(_finding_to_dict(finding))

        if verdict.is_shadow and first_asset_ref is not None:
            findings.append(_finding_to_dict(shadow_finding(workload, verdict, first_asset_ref)))

    for image_id, image in image_refs_seen.items():
        assets.append(_image_asset(image, provider, environment))

    return {
        "connector": {
            "name": "Kubernetes Cartographer",
            "connector_type": "k8s_scanner",
            "status": "manual",
            "scope": {"kubernetes_clusters": [cluster_name]},
            "config": {"scanner": scanner_version, "trusted_registries": trusted_registries},
        },
        "scan_metadata": {
            "status": "running",
            "started_at": now_iso(),
            "scanner_version": scanner_version,
        },
        "assets": assets,
        "components": [],
        "component_usages": [],
        "relationships": relationships,
        "findings": findings,
        "raw_sboms": [],
    }


def _finding_to_dict(finding) -> dict[str, Any]:
    return {
        "asset_ref": finding.asset_ref,
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "fix_recommendation": finding.fix_recommendation,
        "evidence": finding.evidence,
    }
