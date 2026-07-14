"""Docker Hub connector.

Docker Hub runs two separate services:

* the Registry v2 API at ``registry-1.docker.io`` — used to PULL images, but its
  ``/v2/_catalog`` is closed, so it cannot enumerate repositories;
* the Hub REST API at ``hub.docker.com/v2`` — which lists a namespace's
  repositories and exposes per-tag push dates.

This connector therefore discovers via the Hub API and lets the core scanner
pull from the registry.

Official Hub API (2026):

* auth   ``POST https://hub.docker.com/v2/auth/token`` ``{identifier, secret}``
         -> ``{access_token}`` used as ``Authorization: Bearer``;
* repos  ``GET /v2/namespaces/{namespace}/repositories?page_size=100`` (follow ``next``);
* tags   ``GET /v2/namespaces/{namespace}/repositories/{repo}/tags?page_size=100``
         -> ``name``, ``tag_last_pushed``, ``digest``.

Config::

    - name: dockerhub-acme
      type: dockerhub
      connection:
        namespaces: [acme, acme-internal]    # required (Hub has no catalog)
        auth: { provider: env, username_env: DH_USER, password_env: DH_PAT }
      scan:
        pushed_within_days: 90
        max_images_per_repo: 5
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..auth.registry_auth import read_docker_credentials, resolve_static_auth
from ..models import ImageTarget, RegistryAuth, split_image_ref
from .base import Connector, ConnectorError

# (method, url, headers, body) -> (status, parsed_json)
HttpJson = Callable[[str, str, "dict[str, str]", "bytes | None"], "tuple[int, Any]"]


def _default_http(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, Any]:
    request = Request(url, headers=headers or {}, data=body, method=method)
    try:
        with urlopen(request, timeout=60) as response:
            raw = response.read()
            return response.status, json.loads(raw or b"{}")
    except HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return exc.code, {}
    except (URLError, json.JSONDecodeError) as exc:
        raise ConnectorError(f"Docker Hub API request failed ({method} {url}): {exc}") from exc


class DockerHubConnector(Connector):
    type = "dockerhub"

    HUB_API = "https://hub.docker.com/v2"
    REGISTRY = "registry-1.docker.io"

    def __init__(
        self,
        source,
        http: HttpJson | None = None,
        docker_creds: tuple[str, str] | None = None,
    ):
        super().__init__(source)
        ns = self.connection.get("namespaces") or self.connection.get("namespace")
        if isinstance(ns, str):
            ns = [ns]
        self.namespaces = [str(n) for n in (ns or []) if n]
        self.namespaces = [n for n in self.namespaces if self.filters.project_allowed(n)]
        if self.filters.max_projects:
            self.namespaces = self.namespaces[: self.filters.max_projects]
        self.images = list(self.connection.get("images") or [])
        if not self.namespaces and not self.images:
            raise ConnectorError(
                f"source '{self.name}': set connection.namespaces (Docker Hub user/org) for "
                "discovery, or list explicit public images under 'images'"
            )
        self.page_size = int(self.connection.get("page_size", 100))
        self.resolve_dates = bool(self.discovery.get("resolve_push_dates", True))
        self._http = http or _default_http
        self._injected_creds = docker_creds
        self._token: str | None = None
        self._username = ""
        self._secret = ""
        self._credential_source = "anonymous"
        self._creds_resolved = False

    # --- auth ------------------------------------------------------------- #
    def _resolve_creds(self) -> None:
        if self._creds_resolved:
            return
        self._creds_resolved = True
        auth_cfg = self.connection.get("auth") or {}
        provider = str(auth_cfg.get("provider") or "").lower()
        # Reuse an existing `docker login` only when explicitly asked.
        if provider == "docker":
            config_path = auth_cfg.get("config_path") or auth_cfg.get("docker_config")
            user, secret = (
                self._injected_creds
                if self._injected_creds is not None
                else read_docker_credentials(config_path=config_path)
            )
            self._username, self._secret = user, secret
            self._credential_source = "docker login" if secret else "anonymous"
            return
        static = resolve_static_auth(auth_cfg) if auth_cfg else None
        if static and static.username and (static.password or static.token):
            self._username = static.username
            self._secret = static.password or static.token
            self._credential_source = static.provider or "env/static"
            return
        # Omitted / provider:none / unset env vars -> anonymous (public images).
        self._credential_source = "anonymous"

    def _login(self) -> None:
        if self._token is not None:
            return
        self._resolve_creds()
        if not (self._username and self._secret):
            return  # anonymous Hub API (public repositories, lower rate limit)
        status, data = self._http(
            "POST",
            f"{self.HUB_API}/auth/token",
            {"Content-Type": "application/json"},
            json.dumps({"identifier": self._username, "secret": self._secret}).encode(),
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if status == 200 and token:
            self._token = token
            return
        raise ConnectorError(
            f"Docker Hub login failed for '{self._username}' using "
            f"{self._credential_source} credentials (HTTP {status})."
        )

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    # --- discovery -------------------------------------------------------- #
    def _paged(self, url: str) -> Iterable[dict[str, Any]]:
        pages = 0
        while url and pages < 10000:
            status, data = self._http("GET", url, self._headers(), None)
            if status != 200 or not isinstance(data, dict):
                if pages == 0:
                    raise ConnectorError(f"Docker Hub API GET {url} returned HTTP {status}")
                break
            for result in data.get("results") or []:
                yield result
            url = data.get("next") or ""
            pages += 1

    @staticmethod
    def _normalize_ts(ts: str) -> str:
        if not ts:
            return ""
        ts = ts.replace("Z", "+00:00")
        return re.sub(r"(\.\d{6})\d+", r"\1", ts)

    def connect(self) -> None:
        self._login()

    def _images_for_repo(self, namespace: str, repo: str) -> list[ImageTarget]:
        tags_url = (
            f"{self.HUB_API}/namespaces/{namespace}/repositories/{repo}/tags"
            f"?page_size={self.page_size}"
        )
        selected: list[ImageTarget] = []
        for tag in self._paged(tags_url):
            name = tag.get("name", "")
            if not name or not self.filters.tag_allowed(name):
                continue
            pushed_at = ""
            if self.resolve_dates:
                pushed_at = self._normalize_ts(
                    tag.get("tag_last_pushed") or tag.get("last_updated") or ""
                )
            if not self.filters.within_push_window(pushed_at):
                continue
            digest = tag.get("digest", "") or ""
            reference = f"{self.REGISTRY}/{namespace}/{repo}:{name}"
            if digest:
                reference = f"{reference}@{digest}"
            selected.append(
                ImageTarget(
                    reference=reference,
                    registry=self.REGISTRY,
                    repository=f"{namespace}/{repo}",
                    tag=name,
                    digest=digest,
                    pushed_at=pushed_at,
                    source=self.name,
                    provider="docker_hub",
                    discovered_via={
                        "connector": "dockerhub",
                        "namespace": namespace,
                        "repository": repo,
                    },
                )
            )
        selected.sort(key=lambda t: t.pushed_at or "", reverse=True)
        if self.filters.max_images_per_repo:
            selected = selected[: self.filters.max_images_per_repo]
        return selected

    def _explicit_targets(self) -> Iterable[ImageTarget]:
        """Scan explicitly-named images directly — no namespace listing, anonymous OK."""
        for ref in self.images:
            repo, tag, digest = split_image_ref(ref)
            repository = repo if "/" in repo else f"library/{repo}"  # bare name -> official image
            if tag and not self.filters.tag_allowed(tag):
                continue
            reference = f"{self.REGISTRY}/{repository}:{tag}"
            if digest:
                reference = f"{reference}@{digest}"
            yield ImageTarget(
                reference=reference,
                registry=self.REGISTRY,
                repository=repository,
                tag=tag,
                digest=digest,
                source=self.name,
                provider="docker_hub",
                discovered_via={"connector": "dockerhub", "explicit": True},
            )

    def discover_images(self) -> Iterable[ImageTarget]:
        if self.images:
            self._resolve_creds()
            yield from self._explicit_targets()
            return
        self._login()
        for namespace in self.namespaces:
            repos_url = f"{self.HUB_API}/namespaces/{namespace}/repositories?page_size={self.page_size}"
            count = 0
            for repo in self._paged(repos_url):
                name = repo.get("name", "")
                if not name:
                    continue
                if not (
                    self.filters.repository_allowed(name)
                    or self.filters.repository_allowed(f"{namespace}/{name}")
                ):
                    continue
                yield from self._images_for_repo(namespace, name)
                count += 1
                if self.filters.max_images and count >= self.filters.max_images:
                    break

    def registry_auth_for(self, target: ImageTarget) -> RegistryAuth | None:
        self._resolve_creds()
        if self._username and self._secret:
            return RegistryAuth(
                username=self._username,
                password=self._secret,
                registry=self.REGISTRY,
                provider="docker",
            )
        return None
