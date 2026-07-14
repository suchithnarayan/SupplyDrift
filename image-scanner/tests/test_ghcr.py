"""Tests for the GHCR connector (GitHub Packages REST API discovery)."""
from __future__ import annotations

import base64
import json

from conftest import registry_cfg

from image_scanner.connectors.ghcr import GhcrConnector


def make_source(connection=None, **filter_kwargs):
    conn = {"owner": "acme", "auth": {"username": "gh", "token": "ghpat"}}
    conn.update(connection or {})
    return registry_cfg("ghcr", "ghcr", conn, **filter_kwargs)


class FakeGitHub:
    """Two container packages (paginated via Link) with versions."""

    def __init__(self):
        self.calls: list[str] = []

    def __call__(self, url, headers):
        self.calls.append(url)
        assert headers.get("Authorization") == "Bearer ghpat"
        assert headers.get("X-GitHub-Api-Version") == "2022-11-28"
        if "/packages?package_type=container" in url:
            if "page=2" in url:
                return 200, {}, json.dumps([{"name": "api"}]).encode()
            link = '<https://api.github.com/orgs/acme/packages?package_type=container&page=2>; rel="next"'
            return 200, {"link": link}, json.dumps([{"name": "web"}]).encode()
        if "/packages/container/web/versions" in url:
            return 200, {}, json.dumps(
                [{"name": "sha256:w1", "updated_at": "2026-05-20T00:00:00Z",
                  "metadata": {"container": {"tags": ["1.4.2", "latest"]}}}]
            ).encode()
        if "/packages/container/api/versions" in url:
            return 200, {}, json.dumps(
                [
                    {"name": "sha256:a1", "updated_at": "2026-05-21T00:00:00Z",
                     "metadata": {"container": {"tags": ["2.0"]}}},
                    {"name": "sha256:a2", "updated_at": "2026-05-22T00:00:00Z",
                     "metadata": {"container": {"tags": []}}},  # untagged
                ]
            ).encode()
        return 404, {}, b"[]"


def test_ghcr_discovers_packages_across_pages():
    conn = GhcrConnector(make_source(include_tags=["*"]), http=FakeGitHub())
    targets = list(conn.discover_images())
    refs = {t.reference for t in targets}
    assert "ghcr.io/acme/web:1.4.2@sha256:w1" in refs
    assert "ghcr.io/acme/web:latest@sha256:w1" in refs
    assert "ghcr.io/acme/api:2.0@sha256:a1" in refs
    # untagged a2 is excluded under the default tagged filter.
    assert not any(t.digest == "sha256:a2" for t in targets)
    assert all(t.provider == "github_ghcr" for t in targets)
    assert all(t.registry == "ghcr.io" for t in targets)


def test_ghcr_untagged_included_when_any():
    conn = GhcrConnector(make_source(tag_status="any"), http=FakeGitHub())
    targets = [t for t in conn.discover_images() if t.repository == "acme/api"]
    assert any(t.digest == "sha256:a2" and t.tag == "" for t in targets)


def test_ghcr_tag_filter():
    conn = GhcrConnector(make_source(include_tags=["1.*"]), http=FakeGitHub())
    refs = {t.reference for t in conn.discover_images()}
    assert refs == {"ghcr.io/acme/web:1.4.2@sha256:w1"}


def test_ghcr_pull_auth_embedded_on_target():
    conn = GhcrConnector(make_source(), http=FakeGitHub())
    target = next(iter(conn.discover_images()))
    assert target.auth is not None
    assert target.auth.username == "gh" and target.auth.password == "ghpat"


def test_ghcr_direct_pull_resolves_explicit_docker_config(tmp_path):
    config = tmp_path / "config.json"
    encoded = base64.b64encode(b"docker-user:docker-pat").decode()
    config.write_text(
        json.dumps({"auths": {"ghcr.io": {"auth": encoded}}}),
        encoding="utf-8",
    )
    conn = GhcrConnector(
        make_source(
            {
                "images": ["acme/public:1"],
                "auth": {"provider": "docker", "config_path": str(config)},
            }
        ),
        http=lambda *args: (500, {}, b""),
    )

    auth = conn.registry_auth_for(None)

    assert auth and auth.username == "docker-user"
    assert auth.password == "docker-pat"
