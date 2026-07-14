"""Kubernetes service connector — discovers images running in every cluster.

This connector does NOT re-implement workload enumeration; it reuses the bundled
``k8s_cartographer`` collector + analyzer to walk workloads and pull out their
container images, then hands each to the source-agnostic core scanner.

It is *exhaustive*: by default it enumerates every context in the kubeconfig (one
per cluster) and every workload in every namespace. Pull credentials are resolved
through the shared :class:`~image_scanner.auth.index.RegistryAuthIndex` — i.e.
the configured registries — so a cluster running a Docker Hub / GHCR / Harbor /
ECR image reuses that registry's authentication.

Config::

    - name: k8s-all
      type: kubernetes
      connection:
        kubeconfig: ~/.kube/config
        contexts: ["*"]              # default: every context (all clusters)
      discovery:
        namespaces: ["*"]
        include_init: true
        include_ephemeral: true
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Callable, Iterable

from ..models import ImageTarget
from .base import ConnectorError, ServiceConnector

from k8s_cartographer import analyzer as k8s_analyzer
from k8s_cartographer import collector as k8s_collector

# (kubeconfig, context, namespace) -> list of raw resource dicts
ClusterCollector = Callable[["str | None", "str | None", "str | None"], list]


class KubernetesConnector(ServiceConnector):
    type = "kubernetes"

    def __init__(self, source, index=None, resources: list | None = None,
                 cluster_collector: ClusterCollector | None = None):
        super().__init__(source, index=index)
        disc = self.discovery
        self.object_kinds = set(disc.get("object_kinds") or list(k8s_analyzer.WORKLOAD_KIND_SET))
        self.include_init = bool(disc.get("include_init_containers", disc.get("include_init", True)))
        self.include_ephemeral = bool(disc.get("include_ephemeral", True))
        self.include_owned = bool(disc.get("include_owned", False))
        self.namespaces = list(disc.get("namespaces") or ["*"])
        ctx = self.connection.get("contexts")
        if isinstance(ctx, str):
            ctx = [ctx]
        self.context_globs = list(ctx or ["*"])
        self._injected_resources = resources
        self._collect_cluster: ClusterCollector = cluster_collector or k8s_collector.collect_from_cluster
        # (cluster_name, [Workload]) captured during discovery so the pipeline can
        # also emit cluster topology (clusters + workloads) — see cartography_payloads.
        self._cartography: list[tuple[str, list]] = []

    # --- source selection ------------------------------------------------- #
    def _offline_resources(self) -> list | None:
        """Return resources from an injected/offline source, else None for live."""
        if self._injected_resources is not None:
            return self._injected_resources
        conn = self.connection
        if conn.get("from_json"):
            return k8s_collector.collect_from_json_file(Path(conn["from_json"]))
        if conn.get("manifests"):
            return k8s_collector.collect_from_manifests(Path(conn["manifests"]))
        return None

    def _contexts(self) -> list[str]:
        """Live contexts to scan (filtered by the configured globs)."""
        kubeconfig = self.connection.get("kubeconfig")
        explicit = [c for c in self.context_globs if "*" not in c and "?" not in c]
        if explicit and self.context_globs == explicit:
            return explicit
        available = k8s_collector.list_contexts(kubeconfig=kubeconfig)
        if not available:
            # No context list (single kubeconfig / in-cluster): use the current one.
            return [self.connection.get("context") or ""]
        return [c for c in available if any(fnmatch.fnmatch(c, g) for g in self.context_globs)]

    def _namespace_allowed(self, namespace: str) -> bool:
        return any(fnmatch.fnmatch(namespace, pat) for pat in self.namespaces)

    def _container_included(self, container_kind: str) -> bool:
        if container_kind == "init":
            return self.include_init
        if container_kind == "ephemeral":
            return self.include_ephemeral
        return True

    def connect(self) -> None:
        try:
            offline = self._offline_resources()
            if offline is None:
                self._collect_cluster(self.connection.get("kubeconfig"), self.connection.get("context"), None)
        except RuntimeError as exc:
            raise ConnectorError(str(exc)) from exc

    # --- discovery -------------------------------------------------------- #
    def _emit(self, resources: list, cluster_name: str) -> Iterable[ImageTarget]:
        workloads = k8s_analyzer.normalize_workloads(
            resources, cluster_name, include_owned=self.include_owned
        )
        # Retain the in-scope workloads (same kind/namespace filtering as discovery)
        # so cartography_payloads() can publish the cluster topology too.
        self._cartography.append((
            cluster_name,
            [
                w for w in workloads
                if w.kind in self.object_kinds and self._namespace_allowed(w.namespace)
            ],
        ))
        seen: set[str] = set()
        for workload in workloads:
            if workload.kind not in self.object_kinds:
                continue
            if not self._namespace_allowed(workload.namespace):
                continue
            for container in workload.containers:
                if not self._container_included(container.kind):
                    continue
                image = container.image
                if image.tag and not self.filters.tag_allowed(image.tag):
                    continue
                if not self.filters.repository_allowed(image.repository):
                    continue
                if image.reference in seen:
                    continue
                seen.add(image.reference)
                yield ImageTarget(
                    reference=image.reference,
                    registry=image.registry,
                    repository=image.repository,
                    tag=image.tag,
                    digest=image.digest,
                    pushed_at="",
                    source=self.name,
                    discovered_via={
                        "connector": self.type,
                        "cluster": workload.cluster,
                        "namespace": workload.namespace,
                        "workload": f"{workload.kind}/{workload.name}",
                        "container": container.name,
                        "container_kind": container.kind,
                        "registry_connection": self.index.describe(image.registry, image.repository),
                    },
                )

    def discover_images(self) -> Iterable[ImageTarget]:
        offline = self._offline_resources()
        if offline is not None:
            cluster = self.connection.get("cluster_name") or self.connection.get("context") or self.name
            yield from self._emit(offline, cluster)
            return
        kubeconfig = self.connection.get("kubeconfig")
        for context in self._contexts():
            resources = self._collect_cluster(kubeconfig, context or None, None)
            cluster = context or self.connection.get("cluster_name") or self.name
            yield from self._emit(resources, cluster)

    # --- cluster topology (Vector 3) -------------------------------------- #
    def cartography_payloads(self, trusted_registries: list[str] | None = None) -> list[dict]:
        """Build ``/api/sync/kubernetes-workloads`` payloads from the workloads
        walked during :meth:`discover_images` — cluster + workload assets, the
        image→workload / workload→cluster relationships, and shadow-deployment /
        image-hygiene findings.

        Container-image identity is aligned to the image-SBOM payloads (see
        :func:`~image_scanner.core.scanner.align_image_asset_identity`) so the
        runtime workload link and the SBOM converge on ONE container_image asset.

        Must be called after ``discover_images`` has been consumed. Returns one
        payload per cluster (empty list if no in-scope workloads were found).
        """
        from k8s_cartographer.payload import build_payload

        from ..core.scanner import align_image_asset_identity

        trusted = trusted_registries
        if trusted is None:
            trusted = self.discovery.get("trusted_registries") or []
        payloads: list[dict] = []
        for cluster_name, workloads in self._cartography:
            if not workloads:
                continue
            payload = build_payload(
                workloads, cluster_name, provider=self.type, trusted_registries=trusted
            )
            align_image_asset_identity(payload)
            # Attribute the topology to THIS source (not a generic cartographer).
            payload.setdefault("connector", {})["name"] = self.name
            if self.source_id:
                payload["connector"]["id"] = self.source_id
            payloads.append(payload)
        return payloads
