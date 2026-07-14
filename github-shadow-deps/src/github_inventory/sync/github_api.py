"""Minimal GitHub REST client to list an org/user's repositories.

Anonymous lists public repos; a PAT (Bearer) lists private + public. Mirrors the
image-scanner GHCR connector's ``Link``-header pagination.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"

# (url, headers) -> (status, response_headers, body)
HttpGet = Callable[[str, "dict[str, str]"], "tuple[int, dict[str, str], bytes]"]


class GithubApiError(RuntimeError):
    """Raised when the GitHub API cannot be reached or returns an error."""


def _default_http(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    request = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(request, timeout=60) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read()
    except URLError as exc:
        raise GithubApiError(f"GitHub API request failed (GET {url}): {exc}") from exc


def _next_link(link_header: str) -> str:
    for part in (link_header or "").split(","):
        match = re.search(r'<([^>]+)>\s*;\s*rel="next"', part)
        if match:
            return match.group(1)
    return ""


class GithubClient:
    def __init__(self, token: str = "", http: HttpGet | None = None):
        self.token = token
        self._http = http or _default_http

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _paged(self, url: str) -> Iterable[dict[str, Any]]:
        pages = 0
        while url and pages < 10000:
            status, headers, body = self._http(url, self._headers())
            if status != 200:
                if pages == 0:
                    hint = "" if self.token else " (set a PAT to list private repos)"
                    raise GithubApiError(f"GitHub API GET {url} returned HTTP {status}{hint}")
                break
            data = json.loads(body or b"[]")
            if isinstance(data, list):
                yield from data
            url = _next_link(headers.get("link", ""))
            pages += 1

    def list_repos(self, owner: str, owner_type: str = "org", visibility: str = "all") -> Iterable[dict[str, Any]]:
        root = "users" if owner_type.lower() in ("user", "users") else "orgs"
        # `type` filters by visibility/affiliation; anonymous only ever sees public.
        repo_type = "all" if visibility == "all" else visibility
        url = f"{API_BASE}/{root}/{quote(owner)}/repos?per_page=100&type={repo_type}"
        yield from self._paged(url)
