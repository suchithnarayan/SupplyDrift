"""Tests for the GitHub repo connector (enumerate vs explicit, auth, filters)."""
from __future__ import annotations

import pytest

from github_inventory.sync.config import SourceConfig, SourceFilters
from github_inventory.sync.connector import GithubConnector


def _source(connection, **filter_kwargs):
    return SourceConfig(name="s", type="github", connection=connection, filters=SourceFilters(**filter_kwargs))


class FakeClient:
    def __init__(self, repos):
        self.repos = repos
        self.calls = []

    def list_repos(self, owner, owner_type, visibility):
        self.calls.append((owner, owner_type, visibility))
        return iter(self.repos)


def test_explicit_repos_no_api():
    conn = GithubConnector(
        _source({"repositories": ["acme/api", "https://github.com/foo/bar"]}),
        client=FakeClient([]),
    )
    targets = list(conn.discover_repos())
    assert {t.full_name for t in targets} == {"acme/api", "foo/bar"}
    assert all(t.clone_url.endswith(".git") for t in targets)
    assert all(t.token == "" for t in targets)  # anonymous (no auth)


def test_enumerate_org_with_globs_and_archived():
    client = FakeClient([
        {"name": "api", "full_name": "acme/api", "clone_url": "https://github.com/acme/api.git",
         "html_url": "https://github.com/acme/api", "default_branch": "main", "private": False},
        {"name": "old", "full_name": "acme/old", "archived": True},
        {"name": "web", "full_name": "acme/web"},
    ])
    conn = GithubConnector(_source({"owner": "acme"}, repositories=["a*"]), client=client)
    names = {t.full_name for t in conn.discover_repos()}
    assert names == {"acme/api"}  # 'web' excluded by glob, 'old' archived-excluded
    assert client.calls == [("acme", "org", "all")]


def test_max_repos_cap():
    client = FakeClient([{"name": f"r{i}", "full_name": f"acme/r{i}"} for i in range(5)])
    conn = GithubConnector(_source({"owner": "acme"}, max_repos=2), client=client)
    assert len(list(conn.discover_repos())) == 2


def test_token_from_env(monkeypatch):
    monkeypatch.setenv("GH_PAT", "ghp_secret")
    conn = GithubConnector(
        _source({"owner": "acme", "auth": {"provider": "env", "token_env": "GH_PAT"}}),
        client=FakeClient([{"name": "api", "full_name": "acme/api"}]),
    )
    target = next(iter(conn.discover_repos()))
    assert target.token == "ghp_secret"


def test_requires_owner_or_explicit():
    from github_inventory.sync.github_api import GithubApiError

    with pytest.raises(GithubApiError, match="owner"):
        GithubConnector(_source({}), client=FakeClient([]))
