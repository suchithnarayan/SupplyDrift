"""Registry auth index — the bridge from services to registries.

A service connector (Kubernetes, ECS, EKS) discovers images by registry host but
has no credentials of its own to PULL them. The user's rule is: *fall back to the
configured registries — if the registry an image came from is already
authenticated as a configured registry, reuse that credential.*

:class:`RegistryAuthIndex` is built once from the configured ``registries`` and
maps a discovered registry host to the pull credential that registry resolved:

* Docker Hub / GHCR / Harbor -> static/env/robot credentials (pre-resolved);
* ECR -> minted on demand from the registry's :class:`~image_scanner.auth.aws.AwsSession`.

When nothing matches, a service may pass its own ``AwsSession`` as the ECR
fallback (an EKS/ECS source authenticated to AWS can still pull an ECR image
whose registry was not separately configured). Otherwise the result is ``None``
(anonymous). Ambient Docker credentials are never exposed to the extractor.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from ..models import RegistryAuth
from .aws import AwsSession
from .registry_auth import (
    is_ecr_registry,
    resolve_pull_auth,
)

DOCKERHUB_HOSTS = ("registry-1.docker.io", "docker.io", "index.docker.io")


def _static_pull_auth(connection: dict[str, Any], host: str) -> RegistryAuth | None:
    """Resolve only the credential source explicitly configured for a registry."""
    return resolve_pull_auth(connection.get("auth"), registry=host)


@dataclass
class _Entry:
    patterns: list[str]
    source: str
    registry_type: str
    auth: RegistryAuth | None = None          # pre-resolved (non-cloud)
    session: AwsSession | None = None          # for ECR (mint lazily)
    region: str = ""

    def matches(self, registry: str, candidate: str) -> bool:
        return any(
            fnmatch.fnmatch(registry, p) or fnmatch.fnmatch(candidate, p)
            for p in self.patterns
        )

    def resolve(self, registry: str) -> RegistryAuth | None:
        if self.registry_type == "ecr" and self.session is not None:
            return self.session.ecr_auth(registry, region=self.region or None)
        return self.auth


class RegistryAuthIndex:
    """Maps a discovered registry host to a configured registry's pull credential."""

    def __init__(self, entries: list[_Entry] | None = None):
        self.entries: list[_Entry] = entries or []
        self._cache: dict[str, RegistryAuth | None] = {}

    @classmethod
    def from_registries(cls, registries: list[Any]) -> "RegistryAuthIndex":
        """Build the index from parsed ``RegistryConfig`` objects.

        Each registry exposes ``.type``, ``.name``, and ``.connection``; ECR
        additionally carries an ``aws_session`` attribute.
        """
        entries: list[_Entry] = []
        for reg in registries:
            rtype = reg.type
            conn = reg.connection
            if rtype == "dockerhub":
                entries.append(
                    _Entry(
                        patterns=[p for h in DOCKERHUB_HOSTS for p in (f"{h}/*", h)],
                        source=reg.name,
                        registry_type="dockerhub",
                        auth=_static_pull_auth(conn, "registry-1.docker.io"),
                    )
                )
            elif rtype == "ghcr":
                entries.append(
                    _Entry(
                        patterns=["ghcr.io/*", "ghcr.io"],
                        source=reg.name,
                        registry_type="ghcr",
                        auth=_static_pull_auth(conn, "ghcr.io"),
                    )
                )
            elif rtype == "harbor":
                host = conn.get("registry") or conn.get("host") or ""
                if host:
                    entries.append(
                        _Entry(
                            patterns=[f"{host}/*", host],
                            source=reg.name,
                            registry_type="harbor",
                            auth=_static_pull_auth(conn, host),
                        )
                    )
            elif rtype == "ecr":
                session = getattr(reg, "aws_session", None)
                account = str(conn.get("account_id", "") or "")
                region = ""
                if session is not None:
                    regions = session.region_list()
                    region = regions[0] if regions else ""
                if account and region:
                    patterns = [f"{account}.dkr.ecr.{region}.amazonaws.com/*",
                                f"{account}.dkr.ecr.{region}.amazonaws.com"]
                else:
                    patterns = ["*.dkr.ecr.*.amazonaws.com/*", "*.dkr.ecr.*.amazonaws.com"]
                entries.append(
                    _Entry(
                        patterns=patterns,
                        source=reg.name,
                        registry_type="ecr",
                        session=session,
                        region=region,
                    )
                )
        return cls(entries)

    def match(self, registry: str, repository: str = "") -> _Entry | None:
        candidate = f"{registry}/{repository}" if repository else registry
        for entry in self.entries:
            if entry.matches(registry, candidate):
                return entry
        return None

    def auth_for(
        self,
        registry: str,
        repository: str = "",
        aws_fallback: AwsSession | None = None,
    ) -> RegistryAuth | None:
        """Pull credential for ``registry`` (reuse a configured registry, else ECR fallback)."""
        if registry in self._cache:
            return self._cache[registry]
        entry = self.match(registry, repository)
        if entry is not None:
            auth = entry.resolve(registry)
        elif aws_fallback is not None and is_ecr_registry(registry):
            auth = aws_fallback.ecr_auth(registry)
        else:
            auth = None
        self._cache[registry] = auth
        return auth

    def describe(self, registry: str, repository: str = "") -> dict[str, Any]:
        """Diagnostic record of how a registry's pull auth was resolved."""
        entry = self.match(registry, repository)
        if entry is None:
            return {"configured": False, "source": "", "type": "", "match": ""}
        return {
            "configured": True,
            "source": entry.source,
            "type": entry.registry_type,
            "match": entry.patterns[0] if entry.patterns else "",
        }
