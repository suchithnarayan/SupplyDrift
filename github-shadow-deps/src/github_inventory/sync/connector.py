"""Enumerate the repositories a GitHub source wants scanned.

Two modes, mirroring the image-scanner registries:
* explicit ``repositories`` list -> scan exactly those (anonymous-cloneable for
  public repos, no API call needed);
* otherwise -> list the org/user's repos via the GitHub API (PAT or anonymous).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .config import SourceConfig
from .github_api import GithubClient

_SLUG_RE = re.compile(r"(?:https?://github\.com/|git@github\.com:)?([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


@dataclass
class RepoTarget:
    full_name: str            # "owner/repo"
    owner: str
    repo: str
    clone_url: str            # https clone URL
    html_url: str
    default_branch: str = ""
    visibility: str = ""
    pushed_at: str = ""
    source_id: str = ""      # platform connector id, when config came from the platform
    token: str = ""           # PAT for private clones ("" = anonymous)
    discovered_via: dict[str, Any] = field(default_factory=dict)


def _token_for(connection: dict[str, Any]) -> str:
    auth = connection.get("auth") or {}
    if str(auth.get("provider") or "").lower() == "none":
        return ""
    return (
        auth.get("token", "")
        or os.environ.get(str(auth.get("token_env") or ""), "")
        or os.environ.get(str(auth.get("password_env") or ""), "")
    )


class GithubConnector:
    type = "github"

    def __init__(self, source: SourceConfig, client: GithubClient | None = None):
        self.source = source
        self.name = source.name
        self.source_id = source.source_id
        self.connection = source.connection
        self.filters = source.filters
        self.owner = self.connection.get("owner") or self.connection.get("namespace") or ""
        self.owner_type = str(self.connection.get("owner_type", "org")).lower()
        self.visibility = str(self.connection.get("visibility", "all")).lower()
        self.explicit = list(self.connection.get("repositories") or [])
        self.token = _token_for(self.connection)
        self._client = client or GithubClient(token=self.token)
        if not self.owner and not self.explicit:
            from .github_api import GithubApiError

            raise GithubApiError(
                f"source '{self.name}': set connection.owner (GitHub org/user), "
                "or list explicit public repos under connection.repositories"
            )

    def _target(self, full_name: str, **extra: Any) -> RepoTarget:
        owner, _, repo = full_name.partition("/")
        return RepoTarget(
            full_name=full_name,
            owner=owner,
            repo=repo,
            clone_url=extra.get("clone_url") or f"https://github.com/{full_name}.git",
            html_url=extra.get("html_url") or f"https://github.com/{full_name}",
            default_branch=extra.get("default_branch", ""),
            visibility=extra.get("visibility", ""),
            pushed_at=extra.get("pushed_at", ""),
            source_id=self.source_id,
            token=self.token,
            discovered_via={"connector": "github", "source": self.name, **extra.get("discovered_via", {})},
        )

    def _explicit_targets(self) -> Iterable[RepoTarget]:
        for ref in self.explicit:
            m = _SLUG_RE.match(str(ref).strip())
            if not m:
                continue
            full_name = f"{m.group(1)}/{m.group(2)}"
            yield self._target(full_name, discovered_via={"explicit": True})

    def discover_repos(self) -> Iterable[RepoTarget]:
        if self.explicit:
            yield from self._explicit_targets()
            return
        count = 0
        for repo in self._client.list_repos(self.owner, self.owner_type, self.visibility):
            name = repo.get("name", "")
            full_name = repo.get("full_name") or f"{self.owner}/{name}"
            if repo.get("archived") and not self.filters.include_archived:
                continue
            if not self.filters.repo_allowed(name, full_name):
                continue
            yield self._target(
                full_name,
                clone_url=repo.get("clone_url"),
                html_url=repo.get("html_url"),
                default_branch=repo.get("default_branch", ""),
                visibility=repo.get("visibility", "private" if repo.get("private") else "public"),
                pushed_at=repo.get("pushed_at", ""),
            )
            count += 1
            if self.filters.max_repos and count >= self.filters.max_repos:
                break
