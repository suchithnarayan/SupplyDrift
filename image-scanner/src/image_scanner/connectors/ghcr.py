"""GitHub Container Registry (ghcr.io) connector.

GHCR is OCI-v2 compliant for pulling known repositories but does NOT support the
Registry-v2 ``/v2/_catalog`` enumeration. Images are therefore discovered via the
GitHub Packages REST API, and pulled from ``ghcr.io`` afterwards.

Official API (2026):

* packages ``GET /orgs/{org}/packages?package_type=container`` (or
  ``/users/{user}/packages``) — paginate via the ``Link`` header, ``per_page=100``;
* versions ``GET /orgs/{org}/packages/container/{package}/versions`` ->
  ``name`` (= manifest digest), ``metadata.container.tags[]``, ``updated_at``;
* auth     classic PAT with scope ``read:packages`` (fine-grained PATs are not
  supported), sent as ``Authorization: Bearer <PAT>``;
* pull     ``ghcr.io`` Registry v2 via HTTP Basic ``username:PAT``.

Config::

    - name: ghcr-acme
      type: ghcr
      connection:
        owner: acme
        owner_type: org           # org | user
        auth: { provider: env, username_env: GH_USER, token_env: GH_PAT }
      scan:
        max_images_per_repo: 5
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from ..auth.registry_auth import resolve_pull_auth
from ..models import ImageTarget, RegistryAuth, split_image_ref
from .base import Connector, ConnectorError

# (url, headers) -> (status, response_headers, body)
HttpGet = Callable[[str, "dict[str, str]"], "tuple[int, dict[str, str], bytes]"]

API_BASE = "https://api.github.com"
REGISTRY = "ghcr.io"
API_VERSION = "2022-11-28"


def _default_http(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    request = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(request, timeout=60) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read()
    except URLError as exc:
        raise ConnectorError(f"GitHub API request failed (GET {url}): {exc}") from exc


def _next_link(link_header: str) -> str:
    # Link: <https://api.github.com/...&page=2>; rel="next", <...>; rel="last"
    for part in (link_header or "").split(","):
        match = re.search(r'<([^>]+)>\s*;\s*rel="next"', part)
        if match:
            return match.group(1)
    return ""


class GhcrConnector(Connector):
    type = "ghcr"

    def __init__(self, source, http: HttpGet | None = None):
        super().__init__(source)
        self.owner = self.connection.get("owner") or self.connection.get("namespace") or ""
        self.images = list(self.connection.get("images") or [])
        # owner is only needed for API discovery; explicit images can carry it.
        if not self.owner and not self.images:
            raise ConnectorError(
                f"source '{self.name}': set connection.owner (GitHub org/user) for discovery, "
                "or list explicit public images under 'images'"
            )
        owner_type = str(self.connection.get("owner_type", "org")).lower()
        self.owner_root = "users" if owner_type in ("user", "users") else "orgs"
        self.visibility = self.connection.get("visibility")
        self.page_size = int(self.connection.get("page_size", 100))
        self.resolve_dates = bool(self.discovery.get("resolve_push_dates", True))
        self._http = http or _default_http
        static = resolve_pull_auth(self.connection.get("auth"), registry=REGISTRY)
        self._username = static.username if static else ""
        self._token = (static.token or static.password) if static else ""

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _paged(self, url: str) -> Iterable[dict[str, Any]]:
        pages = 0
        while url and pages < 10000:
            status, headers, body = self._http(url, self._headers())
            if status != 200:
                if pages == 0:
                    raise ConnectorError(
                        f"GitHub API GET {url} returned HTTP {status}. GHCR discovery needs a "
                        "classic PAT with the 'read:packages' scope."
                    )
                break
            data = json.loads(body or b"[]")
            if isinstance(data, list):
                yield from data
            url = _next_link(headers.get("link", ""))
            pages += 1

    def connect(self) -> None:
        if self.images:
            return  # explicit images: nothing to validate against the API
        next(iter(self._packages()), None)

    def _packages(self) -> Iterable[dict[str, Any]]:
        url = f"{API_BASE}/{self.owner_root}/{quote(str(self.owner))}/packages?package_type=container&per_page={self.page_size}"
        if self.visibility:
            url += f"&visibility={self.visibility}"
        yield from self._paged(url)

    def _versions(self, package: str) -> Iterable[dict[str, Any]]:
        encoded = quote(package, safe="")
        url = (
            f"{API_BASE}/{self.owner_root}/{quote(str(self.owner))}"
            f"/packages/container/{encoded}/versions?per_page={self.page_size}"
        )
        yield from self._paged(url)

    def _targets_for_package(self, package: str) -> list[ImageTarget]:
        repository = f"{self.owner}/{package}"
        selected: list[ImageTarget] = []
        for version in self._versions(package):
            digest = version.get("name", "") or ""
            if not digest.startswith("sha256:"):
                continue
            pushed_at = (version.get("updated_at") or version.get("created_at") or "") if self.resolve_dates else ""
            if not self.filters.within_push_window(pushed_at):
                continue
            tags = ((version.get("metadata") or {}).get("container") or {}).get("tags") or []
            allowed = [t for t in tags if self.filters.tag_allowed(t)]
            status = self.filters.tag_status
            if allowed and status != "untagged":
                for tag in allowed:
                    selected.append(
                        self._target(repository, tag=tag, digest=digest, pushed_at=pushed_at)
                    )
            elif not tags and status != "tagged":
                selected.append(self._target(repository, tag="", digest=digest, pushed_at=pushed_at))
        selected.sort(key=lambda t: t.pushed_at or "", reverse=True)
        if self.filters.max_images_per_repo:
            selected = selected[: self.filters.max_images_per_repo]
        return selected

    def _target(self, repository: str, *, tag: str, digest: str, pushed_at: str) -> ImageTarget:
        reference = f"{REGISTRY}/{repository}"
        if tag:
            reference = f"{reference}:{tag}"
        if digest:
            reference = f"{reference}@{digest}"
        return ImageTarget(
            reference=reference,
            registry=REGISTRY,
            repository=repository,
            tag=tag,
            digest=digest,
            pushed_at=pushed_at,
            source=self.name,
            provider="github_ghcr",
            discovered_via={"connector": "ghcr", "owner": self.owner, "package": repository},
            auth=self.registry_auth_for(None),
        )

    def _explicit_targets(self) -> Iterable[ImageTarget]:
        """Scan explicitly-named images directly — no Packages API, anonymous OK.

        This is the only way to scan PUBLIC GHCR images without a token, since the
        GitHub Packages API requires authentication even for public packages.
        """
        for ref in self.images:
            repo, tag, digest = split_image_ref(ref)
            repository = repo if "/" in repo else (f"{self.owner}/{repo}" if self.owner else repo)
            if "/" not in repository:
                raise ConnectorError(
                    f"source '{self.name}': image '{ref}' needs an owner (use 'owner/repo' or set connection.owner)"
                )
            if tag and not self.filters.tag_allowed(tag):
                continue
            yield self._target(repository, tag=tag, digest=digest, pushed_at="")

    def discover_images(self) -> Iterable[ImageTarget]:
        if self.images:
            yield from self._explicit_targets()
            return
        if not self._token:
            raise ConnectorError(
                f"source '{self.name}': GHCR discovery needs a classic PAT with 'read:packages'. "
                "For public images without a token, list them under 'images' instead."
            )
        count = 0
        for package in self._packages():
            name = package.get("name", "")
            if not name:
                continue
            if not (
                self.filters.repository_allowed(name)
                or self.filters.repository_allowed(f"{self.owner}/{name}")
            ):
                continue
            yield from self._targets_for_package(name)
            count += 1
            if self.filters.max_images and count >= self.filters.max_images:
                break

    def registry_auth_for(self, target: ImageTarget | None) -> RegistryAuth | None:
        if self._username and self._token:
            return RegistryAuth(
                username=self._username,
                password=self._token,
                registry=REGISTRY,
                provider="ghcr",
            )
        return None
