"""Core data model shared by the scanner core and every connector.

The pivotal type is ``ImageTarget``: no matter how a connector discovered an
image (registry catalog walk, ECR API, Kubernetes workload inspection, ...), it
yields the same record, so the core scanner never has to know the source.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def split_image_ref(ref: str, default_tag: str = "latest") -> tuple[str, str, str]:
    """Split ``repo[:tag][@digest]`` into ``(repository, tag, digest)``.

    The tag colon is only honored in the final path segment so a registry port
    (``host:5000/repo``) is never mistaken for a tag.
    """
    ref = (ref or "").strip()
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    repo, tag = ref, default_tag
    if ":" in ref.rsplit("/", 1)[-1]:
        repo, tag = ref.rsplit(":", 1)
    return repo, tag, digest


@dataclass
class RegistryAuth:
    """Credentials/intent used to pull an image from a registry.

    A resolved auth object can carry explicit credentials OR simply express how
    the extractor should authenticate natively:

    * ``username``/``password``/``token`` - explicit credentials.
    * ``docker_config_path`` - tell the trusted parent where to resolve a prior
      ``docker login``; the parent passes only the single registry credential
      into the sandbox, never the Docker config itself.
    * ``anonymous`` - the caller deliberately wants no credentials.

    ``provider`` records which auth provider produced this object (for logging
    and debugging only). ``None`` (no RegistryAuth at all) means an anonymous
    pull. Docker config and helper credentials are resolved by the trusted
    parent before Syft enters its capability sandbox.
    """

    username: str = ""
    password: str = ""
    token: str = ""  # bearer token (used by some registries instead of user/pass)
    registry: str = ""
    docker_config_path: str = ""
    anonymous: bool = False
    provider: str = ""  # none|static|env|docker|ecr|ghcr|harbor (informational)
    expires_at: float = 0.0  # epoch seconds; 0 == no known expiry (informational)

    @property
    def has_credentials(self) -> bool:
        return bool(self.username or self.password or self.token)

    @property
    def empty(self) -> bool:
        # Retained for back-compat: "empty" means no explicit credentials.
        return not self.has_credentials


@dataclass
class ImageTarget:
    """A single image a connector wants the core scanner to analyze."""

    reference: str  # pullable: registry/repo[:tag][@sha256:...]
    registry: str = ""
    repository: str = ""
    tag: str = ""
    digest: str = ""
    pushed_at: str = ""  # ISO timestamp; "" when the source has no reliable date
    source: str = ""  # connector/source name that produced this target
    source_id: str = ""  # platform connector id, when discovered from platform config
    provider: str = ""  # platform provider tag (aws_ecr, gcr, docker_hub, ...)
    discovered_via: dict[str, Any] = field(default_factory=dict)
    auth: RegistryAuth | None = None

    @property
    def image_name(self) -> str:
        return self.repository.rsplit("/", 1)[-1] if self.repository else self.reference

    @property
    def dedup_key(self) -> str:
        # Prefer the immutable digest; fall back to the full reference.
        if self.digest:
            return f"{self.registry}/{self.repository}@{self.digest}"
        return self.reference


@dataclass
class ImageFilter:
    """Selection rules applied while a connector enumerates images."""

    tag_status: str = "tagged"  # tagged | untagged | any
    pushed_within_days: int | None = None
    max_images_per_repo: int | None = None
    max_projects: int | None = None
    max_images: int | None = None
    include_tags: list[str] = field(default_factory=lambda: ["*"])
    exclude_tags: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=lambda: ["*"])
    projects: list[str] = field(default_factory=lambda: ["*"])

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ImageFilter":
        data = data or {}
        return cls(
            tag_status=str(data.get("tag_status", "tagged")).lower(),
            pushed_within_days=data.get("pushed_within_days"),
            max_images_per_repo=data.get(
                "max_images_per_repo",
                data.get("latest_versions", data.get("max_tags_per_image")),
            ),
            max_projects=data.get("max_projects"),
            max_images=data.get("max_images"),
            include_tags=list(data.get("include_tags", ["*"])) or ["*"],
            exclude_tags=list(data.get("exclude_tags", [])),
            repositories=list(data.get("repositories", ["*"])) or ["*"],
            projects=list(data.get("projects", ["*"])) or ["*"],
        )

    def project_allowed(self, project: str) -> bool:
        return any(fnmatch.fnmatch(project, pat) for pat in self.projects)

    def repository_allowed(self, repository: str) -> bool:
        if not any(fnmatch.fnmatch(repository, pat) for pat in self.repositories):
            return False
        if self.projects == ["*"]:
            return True
        project = repository.split("/", 1)[0] if "/" in repository else ""
        return self.project_allowed(project)

    def tag_allowed(self, tag: str) -> bool:
        if self.exclude_tags and any(fnmatch.fnmatch(tag, pat) for pat in self.exclude_tags):
            return False
        return any(fnmatch.fnmatch(tag, pat) for pat in self.include_tags)

    def within_push_window(self, pushed_at: str) -> bool:
        if not self.pushed_within_days:
            return True
        if not pushed_at:
            # No timestamp available -> do not exclude (best effort).
            return True
        try:
            ts = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - ts).total_seconds() / 86400.0
        return age_days <= self.pushed_within_days


@dataclass
class ScanResult:
    """Output of scanning one image: a CycloneDX SBOM plus asset context."""

    target: ImageTarget
    cyclonedx: dict[str, Any]
    component_count: int = 0
    vuln_count: int = 0
    extractor: str = ""
    error: str = ""
    vuln_error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error
