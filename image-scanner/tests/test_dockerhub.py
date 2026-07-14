"""Tests for the Docker Hub connector (Hub API discovery + login reuse)."""
from __future__ import annotations

import json

import pytest
from conftest import registry_cfg

from image_scanner.connectors.base import ConnectorError
from image_scanner.connectors import dockerhub as dockerhub_module
from image_scanner.connectors.dockerhub import DockerHubConnector


def make_source(connection, **filter_kwargs):
    return registry_cfg("hub", "dockerhub", connection, **filter_kwargs)


class FakeHub:
    """A canned Docker Hub API: one namespace, two repos, with tags."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        self.repos = {"acme": ["api", "web"]}
        self.tags = {
            "acme/api": [
                {"name": "1.0", "digest": "sha256:api10", "tag_last_pushed": "2026-05-20T10:00:00.123456789Z"},
                {"name": "latest", "digest": "sha256:apilatest", "tag_last_pushed": "2026-05-25T10:00:00Z"},
                {"name": "old", "digest": "sha256:apiold", "tag_last_pushed": "2020-01-01T00:00:00Z"},
            ],
            "acme/web": [
                {"name": "2.0", "digest": "sha256:web20", "tag_last_pushed": "2026-05-21T10:00:00Z"},
            ],
        }

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        if url.endswith("/auth/token"):
            assert method == "POST"
            creds = json.loads(body)
            if creds.get("identifier") == "robot" and creds.get("secret") == "pat":
                return 200, {"access_token": "TOK"}
            return 401, {"detail": "bad creds"}
        if "/namespaces/acme/repositories?" in url:
            return 200, {"results": [{"name": n} for n in self.repos["acme"]], "next": None}
        for repo, tags in self.tags.items():
            if f"/repositories/{repo.split('/')[1]}/tags" in url:
                return 200, {"results": tags, "next": None}
        return 404, {}


def test_dockerhub_requires_namespace():
    with pytest.raises(ConnectorError, match="namespaces"):
        DockerHubConnector(make_source({}))


def test_dockerhub_discovers_using_login(monkeypatch):
    monkeypatch.setenv("U", "robot")
    monkeypatch.setenv("P", "pat")
    hub = FakeHub()
    conn = DockerHubConnector(
        make_source({"namespaces": ["acme"], "auth": {"provider": "env", "username_env": "U", "password_env": "P"}}),
        http=hub,
    )
    targets = list(conn.discover_images())
    refs = sorted(t.reference for t in targets)
    assert "registry-1.docker.io/acme/api:1.0@sha256:api10" in refs
    assert "registry-1.docker.io/acme/web:2.0@sha256:web20" in refs
    assert {t.repository for t in targets} == {"acme/api", "acme/web"}
    assert all(t.provider == "docker_hub" for t in targets)
    assert ("POST", "https://hub.docker.com/v2/auth/token") in hub.calls


def test_dockerhub_reuses_docker_login_credentials():
    hub = FakeHub()
    conn = DockerHubConnector(
        make_source({"namespaces": ["acme"], "auth": {"provider": "docker"}}),  # opt in to docker login
        http=hub,
        docker_creds=("robot", "pat"),
    )
    targets = list(conn.discover_images())
    assert targets
    auth = conn.registry_auth_for(targets[0])
    assert auth is not None and auth.username == "robot" and auth.password == "pat"
    assert auth.registry == "registry-1.docker.io"


def test_dockerhub_uses_explicit_docker_config_path(monkeypatch):
    captured = {}

    def fake_read(registry="https://index.docker.io/v1/", config_path=None, **kwargs):
        captured.update(registry=registry, config_path=config_path)
        return "robot", "pat"

    monkeypatch.setattr(dockerhub_module, "read_docker_credentials", fake_read)
    conn = DockerHubConnector(
        make_source(
            {
                "images": ["nginx:latest"],
                "auth": {
                    "provider": "docker",
                    "config_path": "/trusted/docker-config.json",
                },
            }
        )
    )

    auth = conn.registry_auth_for(None)

    assert captured["config_path"] == "/trusted/docker-config.json"
    assert auth and auth.username == "robot" and auth.password == "pat"


def test_dockerhub_push_window_and_cap():
    hub = FakeHub()
    conn = DockerHubConnector(
        make_source({"namespaces": ["acme"]}, pushed_within_days=365, max_images_per_repo=1),
        http=hub,
        docker_creds=("robot", "pat"),
    )
    targets = [t for t in conn.discover_images() if t.repository == "acme/api"]
    assert len(targets) == 1
    assert targets[0].tag == "latest"  # newest by push date


def test_dockerhub_anonymous_when_no_creds():
    hub = FakeHub()
    conn = DockerHubConnector(
        make_source({"namespaces": ["acme"], "auth": {"provider": "none"}}),
        http=hub,
        docker_creds=("", ""),
    )
    conn._login()
    assert conn._token is None
    assert conn._headers() == {}


def test_dockerhub_login_failure_is_fatal():
    hub = FakeHub()
    conn = DockerHubConnector(
        make_source({"namespaces": ["acme"], "auth": {"provider": "docker"}}),
        http=hub,
        docker_creds=("robot", "wrongpass"),
    )
    with pytest.raises(ConnectorError, match="login failed"):
        conn._login()
