"""Parse OCI image references into registry / repository / tag / digest.

Follows the same resolution rules the Docker/containerd clients use so that the
scanner reports the registry a workload actually pulls from, and whether the
reference is digest-pinned (immutable) or tag-pinned (mutable).
"""
from __future__ import annotations

from .models import ImageRef

DEFAULT_REGISTRY = "docker.io"


def _looks_like_registry(component: str) -> bool:
    # The first path component is a registry host if it contains a dot, a port
    # colon, or is the special "localhost" host. Otherwise it is part of the
    # repository on the implicit Docker Hub registry.
    return "." in component or ":" in component or component == "localhost"


def parse_image_reference(raw: str) -> ImageRef:
    """Parse a raw image string such as ``ghcr.io/acme/api:1.2@sha256:ab...``."""
    ref = (raw or "").strip()
    digest = ""
    remainder = ref

    if "@" in remainder:
        remainder, digest = remainder.split("@", 1)

    # Separate an optional registry host from the repository path.
    registry = ""
    path = remainder
    if "/" in remainder:
        first, rest = remainder.split("/", 1)
        if _looks_like_registry(first):
            registry = first
            path = rest

    # The tag is the segment after the last ":" in the final path element,
    # taking care not to confuse a registry port for a tag.
    tag = ""
    repository = path
    if ":" in path:
        repo_candidate, tag_candidate = path.rsplit(":", 1)
        if "/" not in tag_candidate:
            repository = repo_candidate
            tag = tag_candidate

    if not registry:
        registry = DEFAULT_REGISTRY
        # Docker Hub official images live under the implicit "library/" namespace.
        if "/" not in repository:
            repository = f"library/{repository}"

    if not tag and not digest:
        tag = "latest"

    name = repository.rsplit("/", 1)[-1]
    return ImageRef(
        raw=ref,
        registry=registry,
        repository=repository,
        name=name,
        tag=tag,
        digest=digest,
    )


def digest_from_image_id(image_id: str) -> str:
    """Extract a ``sha256:...`` digest from a pod containerStatus imageID."""
    if not image_id:
        return ""
    if "@" in image_id:
        return image_id.split("@", 1)[1]
    if image_id.startswith("sha256:"):
        return image_id
    return ""
