"""Connector registry and factory.

Maps a source ``type`` to a connector class. Registry connectors are
config-scoped; service connectors are exhaustive and pull through the shared
:class:`~image_scanner.auth.index.RegistryAuthIndex`.
"""
from __future__ import annotations

from typing import Any

from .base import Connector, ConnectorError, ServiceConnector
from .dockerhub import DockerHubConnector
from .ecr import EcrConnector
from .ecs import EcsConnector
from .eks import EksConnector
from .ghcr import GhcrConnector
from .harbor import HarborConnector
from .kubernetes import KubernetesConnector

REGISTRY_CONNECTORS: dict[str, type[Connector]] = {
    DockerHubConnector.type: DockerHubConnector,
    GhcrConnector.type: GhcrConnector,
    HarborConnector.type: HarborConnector,
    EcrConnector.type: EcrConnector,
}

SERVICE_CONNECTORS: dict[str, type[Connector]] = {
    KubernetesConnector.type: KubernetesConnector,
    EksConnector.type: EksConnector,
    EcsConnector.type: EcsConnector,
}

CONNECTORS: dict[str, type[Connector]] = {**REGISTRY_CONNECTORS, **SERVICE_CONNECTORS}

__all__ = [
    "Connector",
    "ConnectorError",
    "ServiceConnector",
    "CONNECTORS",
    "REGISTRY_CONNECTORS",
    "SERVICE_CONNECTORS",
    "build_connector",
]


def build_connector(source: Any, index: Any = None) -> Connector:
    connector_cls = CONNECTORS.get(source.type)
    if connector_cls is None:
        raise ConnectorError(
            f"source '{source.name}': unknown type '{source.type}'. "
            f"Known types: {', '.join(sorted(CONNECTORS))}"
        )
    if issubclass(connector_cls, ServiceConnector):
        return connector_cls(source, index=index)
    return connector_cls(source)
