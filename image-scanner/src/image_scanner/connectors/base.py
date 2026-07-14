"""The connector interface — the source-specific "orchestrator".

Every connector, however it discovers images, yields the same ``ImageTarget``
records so the core scanner stays source-agnostic. Two broad shapes exist:

* **registry connectors** (Docker Hub, GHCR, Harbor, ECR): config-scoped —
  list projects -> repositories -> tags, narrowed by the source's filters.
* **service connectors** (Kubernetes, ECS, EKS): exhaustive — enumerate every
  running workload in every cluster, extract image refs, and resolve the pull
  credential via the shared :class:`~image_scanner.auth.index.RegistryAuthIndex`.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable

from ..models import ImageTarget, RegistryAuth


class ConnectorError(RuntimeError):
    """Raised when a connector cannot connect or enumerate images."""


class Connector(ABC):
    type: str = "base"

    def __init__(self, source: Any):
        self.source = source
        self.name = source.name
        self.source_id = getattr(source, "source_id", "") or getattr(source, "id", "")
        self.filters = source.filters
        self.connection = source.connection
        self.discovery = getattr(source, "discovery", {}) or {}

    def connect(self) -> None:
        """Validate access to the source. Override when a check is possible."""
        return None

    @abstractmethod
    def discover_images(self) -> Iterable[ImageTarget]:
        """Yield the images this source wants scanned (filters applied)."""

    def registry_auth_for(self, target: ImageTarget) -> RegistryAuth | None:
        """Credentials to pull a discovered image. Default: whatever the target carries."""
        return target.auth


class ServiceConnector(Connector):
    """Base for exhaustive service connectors that pull via the registry index."""

    def __init__(self, source: Any, index: Any = None):
        super().__init__(source)
        from ..auth.index import RegistryAuthIndex

        self.index = index if index is not None else RegistryAuthIndex()
        self.aws_session = getattr(source, "aws_session", None)
        self._auth_cache: dict[str, RegistryAuth | None] = {}

    def registry_auth_for(self, target: ImageTarget) -> RegistryAuth | None:
        if target.registry in self._auth_cache:
            auth = self._auth_cache[target.registry]
        else:
            auth = self.index.auth_for(
                target.registry, target.repository, aws_fallback=self.aws_session
            )
            self._auth_cache[target.registry] = auth
        conn = target.discovered_via.get("registry_connection") or self.index.describe(
            target.registry, target.repository
        )
        conn = {**conn, "auth_provider": auth.provider if auth else ""}
        target.discovered_via["registry_connection"] = conn
        return auth
