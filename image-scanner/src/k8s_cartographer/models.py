"""Data model for the Kubernetes cartography scanner.

The scanner walks a cluster (or an offline dump of it), turns every container of
every workload into a normalized record, then renders those records into the
SupplyDrift sync payload shape (`assets` / `components` / `relationships` /
`findings`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Workload kinds the scanner enumerates. Mirrors the PDF (Deployments,
# StatefulSets, DaemonSets, CronJobs, Jobs, ReplicaSets) plus bare Pods, which
# are the classic "kubectl run" shadow-deployment vehicle.
WORKLOAD_KINDS = (
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "CronJob",
    "Job",
    "ReplicaSet",
    "Pod",
)

# kubectl resource names (plural) used when collecting from a live cluster.
KUBECTL_RESOURCES = (
    "deployments",
    "statefulsets",
    "daemonsets",
    "cronjobs",
    "jobs",
    "replicasets",
    "pods",
)


@dataclass
class ImageRef:
    """A parsed container image reference."""

    raw: str
    registry: str
    repository: str
    name: str
    tag: str
    digest: str

    @property
    def pinned(self) -> bool:
        """True when the reference is immutable (digest-pinned)."""
        return bool(self.digest)

    @property
    def mutable_tag(self) -> bool:
        """True when the tag can silently change content over time."""
        return self.tag.lower() in MUTABLE_TAGS or (not self.tag and not self.digest)

    @property
    def reference(self) -> str:
        base = f"{self.registry}/{self.repository}" if self.registry else self.repository
        if self.tag:
            base = f"{base}:{self.tag}"
        if self.digest:
            base = f"{base}@{self.digest}"
        return base


MUTABLE_TAGS = {
    "latest",
    "main",
    "master",
    "stable",
    "edge",
    "dev",
    "develop",
    "devel",
    "nightly",
    "rolling",
    "head",
    "snapshot",
    "current",
}


@dataclass
class Container:
    """A single container inside a workload (app, init, sidecar, or ephemeral)."""

    name: str
    image: ImageRef
    kind: str = "container"  # container | init | ephemeral
    resolved_digest: str = ""  # digest observed at runtime (pod status), if any


@dataclass
class Workload:
    """A normalized workload (the root controller or a bare pod)."""

    cluster: str
    namespace: str
    kind: str
    name: str
    uid: str = ""
    service_account: str = ""
    node_name: str = ""
    containers: list[Container] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    managers: list[str] = field(default_factory=list)
    owner_kinds: list[str] = field(default_factory=list)
    replicas: int | None = None
    raw_kind_path: str = ""  # e.g. apps/v1 Deployment

    def external_id(self, container_name: str) -> str:
        return f"{self.cluster}/{self.namespace}/{self.kind}/{self.name}/{container_name}"

    @property
    def slug(self) -> str:
        return f"{self.cluster}/{self.namespace}/{self.kind}/{self.name}"


@dataclass
class ShadowVerdict:
    """Result of the shadow-deployment heuristic for one workload."""

    is_shadow: bool
    confidence: str  # high | medium | low
    reasons: list[str] = field(default_factory=list)
    provenance: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A normalized SupplyDrift finding tied to a workload asset."""

    asset_ref: str
    finding_type: str
    severity: str
    title: str
    description: str
    fix_recommendation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
