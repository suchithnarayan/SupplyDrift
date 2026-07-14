"""Harbor connector (Harbor v2 REST API).

Harbor exposes a first-class project/repository/artifact API that gives digests,
tags, and push times directly — better than the generic Registry-v2 catalog.

Official API (2026, ``/api/v2.0``):

* projects  ``GET /api/v2.0/projects?page&page_size``;
* repos     ``GET /api/v2.0/projects/{project}/repositories?page&page_size``;
* artifacts ``GET /api/v2.0/projects/{project}/repositories/{repo}/artifacts?with_tag=true``
            -> ``digest``, ``tags[].name``, ``push_time``;
* auth      HTTP Basic with a robot account full name (``robot$project+name``)
            and its secret; the same credential pulls from the Harbor host.

A nested repository name must be DOUBLE URL-encoded in the artifacts path
(``team/app`` -> ``team%252Fapp``; goharbor/harbor#19635).

Config::

    - name: harbor-prod
      type: harbor
      connection:
        url: https://harbor.acme.io
        auth: { provider: env, username_env: HARBOR_ROBOT, password_env: HARBOR_SECRET }
      scan:
        projects: ["team-*"]
"""
from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from ..auth.registry_auth import resolve_pull_auth
from ..models import ImageTarget, RegistryAuth, split_image_ref
from .base import Connector, ConnectorError

# (url, headers) -> (status, response_headers, body)
HttpGet = Callable[[str, "dict[str, str]"], "tuple[int, dict[str, str], bytes]"]


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject any address that could reach the link-local metadata endpoint
    (169.254.169.254), private RFC1918 ranges, the loopback, or otherwise
    internal infrastructure — the surface an SSRF would target."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _validate_url_scheme_host(url: str, *, where: str) -> tuple[str, str]:
    """Check the URL has a host and an ``https`` (or loopback-``http``) scheme.

    Returns ``(scheme, host)``. Raises :class:`ConnectorError` for a missing host
    or a scheme other than http/https. Does NOT resolve DNS — that is the
    network-facing check in :func:`_validate_public_url`.
    """
    split = urlsplit(url)
    scheme = (split.scheme or "").lower()
    host = split.hostname or ""
    if not host:
        raise ConnectorError(f"{where}: connection.url '{url}' has no host")
    if scheme not in ("https", "http"):
        raise ConnectorError(
            f"{where}: connection.url must use https (got scheme '{scheme}')"
        )
    return scheme, host


def _validate_public_url(url: str, *, where: str) -> None:
    """Validate a tenant-controlled Harbor URL against SSRF.

    Requires an ``https`` scheme (``http`` is allowed ONLY for a loopback host so
    local testing works) and rejects the URL if *any* address the hostname
    resolves to is private/loopback/link-local/reserved/multicast/unspecified.
    Raises :class:`ConnectorError` on violation. The robot ``Basic`` credential
    rides on every request, so a bad URL would exfiltrate it — hence this is a
    hard gate, run before any request is issued on the real network path.
    """
    scheme, host = _validate_url_scheme_host(url, where=where)
    port = urlsplit(url).port or None

    # Resolve every address the host maps to.
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ConnectorError(f"{where}: connection.url host '{host}' did not resolve: {exc}") from exc
    resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        try:
            resolved.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    if not resolved:
        raise ConnectorError(f"{where}: connection.url host '{host}' did not resolve to an IP")

    # http is tolerated ONLY when every resolved address is loopback (pure local
    # testing); loopback then bypasses the internal-range block. Any other
    # internal target — metadata endpoint, RFC1918, link-local — is refused, and
    # a non-loopback http URL is rejected to keep the credential on TLS.
    if scheme == "http" and all(ip.is_loopback for ip in resolved):
        return
    if scheme == "http":
        raise ConnectorError(
            f"{where}: connection.url must use https for non-loopback host '{host}'"
        )
    for ip in resolved:
        if _is_blocked_ip(ip):
            raise ConnectorError(
                f"{where}: connection.url host '{host}' resolves to a "
                f"private/loopback/link-local address ({ip}); refusing to connect"
            )


class _NoRedirect(HTTPRedirectHandler):
    """Refuse to follow redirects: a 3xx to an attacker/internal host would
    replay the robot Authorization header off-Harbor. Callers must re-validate
    and re-issue against a vetted URL instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise ConnectorError(
            f"Harbor API redirected to '{newurl}' (HTTP {code}); refusing to follow "
            "a redirect that would replay credentials to another host"
        )


# Opener that carries no redirect handler chain of its own — the _NoRedirect
# handler turns any 3xx into a hard error instead of silently following it.
_NO_REDIRECT_OPENER = build_opener(_NoRedirect())


def _default_http(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    request = Request(url, headers=headers or {}, method="GET")
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=60) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read()
    except URLError as exc:
        # A _NoRedirect ConnectorError bubbles up wrapped in URLError.reason.
        if isinstance(getattr(exc, "reason", None), ConnectorError):
            raise exc.reason
        raise ConnectorError(f"Harbor API request failed (GET {url}): {exc}") from exc


def _double_encode(repo_subpath: str) -> str:
    """Encode a (possibly nested) repository name for the artifacts path.

    ``team/app`` -> ``team%252Fapp`` (Harbor decodes once before routing).
    """
    return quote(quote(repo_subpath, safe=""), safe="")


class HarborConnector(Connector):
    type = "harbor"

    def __init__(self, source, http: HttpGet | None = None):
        super().__init__(source)
        self.url = (self.connection.get("url") or "").rstrip("/")
        self.host = self.connection.get("registry") or ""
        if not self.url or not self.host:
            raise ConnectorError(f"source '{self.name}': connection.url is required for Harbor")
        # The base URL is tenant-controlled and the robot credential rides every
        # request, so validate it against SSRF. The scheme/host shape is always
        # checked; the DNS-resolution + internal-IP block guards the real network
        # transport (a custom ``http`` is an injected/mock transport that issues
        # no real sockets, so resolving its host would be wrong).
        where = f"source '{self.name}'"
        if http is None:
            _validate_public_url(self.url, where=where)
        else:
            _validate_url_scheme_host(self.url, where=where)
        self.api = f"{self.url}/api/v2.0"
        self.images = list(self.connection.get("images") or [])
        self.page_size = int(self.connection.get("page_size", 50))
        self.resolve_dates = bool(self.discovery.get("resolve_push_dates", True))
        self._http = http or _default_http
        static = resolve_pull_auth(self.connection.get("auth"), registry=self.host)
        self._username = static.username if static else ""
        self._secret = (static.password or static.token) if static else ""

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._username and self._secret:
            import base64

            raw = f"{self._username}:{self._secret}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        return headers

    def _paged(self, path: str, params: str = "") -> Iterable[dict[str, Any]]:
        page = 1
        while page < 10000:
            sep = "&" if params else ""
            url = f"{self.api}{path}?page={page}&page_size={self.page_size}{sep}{params}"
            status, headers, body = self._http(url, self._headers())
            if status != 200:
                if page == 1:
                    raise ConnectorError(f"Harbor API GET {url} returned HTTP {status}")
                break
            items = json.loads(body or b"[]")
            if not isinstance(items, list) or not items:
                break
            yield from items
            if len(items) < self.page_size:
                break
            page += 1

    def connect(self) -> None:
        if self.images:
            return  # explicit images: nothing to validate against the API
        next(iter(self._paged("/projects")), None)

    def _projects(self) -> list[str]:
        names = []
        for project in self._paged("/projects"):
            name = project.get("name", "")
            if name and self.filters.project_allowed(name):
                names.append(name)
        if self.filters.max_projects:
            names = names[: self.filters.max_projects]
        return names

    def _repositories(self, project: str) -> Iterable[str]:
        for repo in self._paged(f"/projects/{quote(project, safe='')}/repositories"):
            full = repo.get("name", "")  # "project/sub/path"
            if not full:
                continue
            sub = full[len(project) + 1:] if full.startswith(f"{project}/") else full
            if self.filters.repository_allowed(sub) or self.filters.repository_allowed(full):
                yield sub

    def _artifacts(self, project: str, repo_sub: str) -> Iterable[dict[str, Any]]:
        path = f"/projects/{quote(project, safe='')}/repositories/{_double_encode(repo_sub)}/artifacts"
        yield from self._paged(path, params="with_tag=true")

    def _targets(self, project: str, repo_sub: str) -> list[ImageTarget]:
        repository = f"{project}/{repo_sub}"
        selected: list[ImageTarget] = []
        for artifact in self._artifacts(project, repo_sub):
            digest = artifact.get("digest", "") or ""
            pushed_at = (artifact.get("push_time") or "") if self.resolve_dates else ""
            if not self.filters.within_push_window(pushed_at):
                continue
            tags = [t.get("name", "") for t in (artifact.get("tags") or []) if t.get("name")]
            allowed = [t for t in tags if self.filters.tag_allowed(t)]
            status = self.filters.tag_status
            if allowed and status != "untagged":
                for tag in allowed:
                    selected.append(self._target(repository, tag, digest, pushed_at))
            elif not tags and status != "tagged":
                selected.append(self._target(repository, "", digest, pushed_at))
        selected.sort(key=lambda t: t.pushed_at or "", reverse=True)
        if self.filters.max_images_per_repo:
            selected = selected[: self.filters.max_images_per_repo]
        return selected

    def _target(self, repository: str, tag: str, digest: str, pushed_at: str) -> ImageTarget:
        reference = f"{self.host}/{repository}"
        if tag:
            reference = f"{reference}:{tag}"
        if digest:
            reference = f"{reference}@{digest}"
        return ImageTarget(
            reference=reference,
            registry=self.host,
            repository=repository,
            tag=tag,
            digest=digest,
            pushed_at=pushed_at,
            source=self.name,
            provider="harbor",
            discovered_via={"connector": "harbor", "project": repository.split("/", 1)[0]},
            auth=self.registry_auth_for(None),
        )

    def _explicit_targets(self) -> Iterable[ImageTarget]:
        """Scan explicitly-named images directly — no projects API, anonymous OK."""
        for ref in self.images:
            repo, tag, digest = split_image_ref(ref)
            # Strip the harbor host if the user included it in the ref.
            if repo.startswith(f"{self.host}/"):
                repo = repo[len(self.host) + 1:]
            if tag and not self.filters.tag_allowed(tag):
                continue
            yield self._target(repo, tag, digest, "")

    def discover_images(self) -> Iterable[ImageTarget]:
        if self.images:
            yield from self._explicit_targets()
            return
        count = 0
        for project in self._projects():
            for repo_sub in self._repositories(project):
                yield from self._targets(project, repo_sub)
                count += 1
                if self.filters.max_images and count >= self.filters.max_images:
                    return

    def registry_auth_for(self, target: ImageTarget | None) -> RegistryAuth | None:
        if self._username and self._secret:
            return RegistryAuth(
                username=self._username,
                password=self._secret,
                registry=self.host,
                provider="harbor",
            )
        return None
