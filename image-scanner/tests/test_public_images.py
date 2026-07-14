"""Credential-less scanning of explicit public images across registries."""
from __future__ import annotations

import pytest
from conftest import registry_cfg

from image_scanner.connectors.base import ConnectorError
from image_scanner.connectors.dockerhub import DockerHubConnector
from image_scanner.connectors.ghcr import GhcrConnector
from image_scanner.connectors.harbor import HarborConnector


def test_dockerhub_explicit_public_images_anonymous():
    conn = DockerHubConnector(
        registry_cfg("dh", "dockerhub", {"images": ["library/nginx:1.27", "alpine:3.19"]})
    )
    targets = list(conn.discover_images())
    refs = {t.reference for t in targets}
    assert "registry-1.docker.io/library/nginx:1.27" in refs
    assert "registry-1.docker.io/library/alpine:3.19" in refs  # bare name -> official image
    # No auth configured -> anonymous pull (None), no Hub login needed.
    assert all(conn.registry_auth_for(t) is None for t in targets)


def test_dockerhub_omitted_auth_is_anonymous():
    conn = DockerHubConnector(registry_cfg("dh", "dockerhub", {"images": ["busybox:latest"]}))
    conn._resolve_creds()
    assert conn._credential_source == "anonymous"


def test_ghcr_explicit_public_images_without_token():
    conn = GhcrConnector(registry_cfg("g", "ghcr", {"images": ["acme/api:1.0", "grafana/grafana:11.0"]}))
    refs = {t.reference for t in conn.discover_images()}
    assert refs == {"ghcr.io/acme/api:1.0", "ghcr.io/grafana/grafana:11.0"}
    assert all(t.auth is None for t in conn.discover_images())  # anonymous


def test_ghcr_bare_image_uses_owner():
    conn = GhcrConnector(registry_cfg("g", "ghcr", {"owner": "acme", "images": ["api:2.0"]}))
    assert {t.reference for t in conn.discover_images()} == {"ghcr.io/acme/api:2.0"}


def test_ghcr_discovery_without_token_errors():
    conn = GhcrConnector(registry_cfg("g", "ghcr", {"owner": "acme"}))  # no token, no images
    with pytest.raises(ConnectorError, match="read:packages"):
        list(conn.discover_images())


def test_harbor_explicit_public_images():
    # Explicit images never call the projects API, so inject a transport that
    # fails if used. This also keeps construction offline: the SSRF URL guard
    # only resolves DNS on the real (default) transport, not an injected one.
    def _no_http(url, headers):  # pragma: no cover - must not be reached
        raise AssertionError(f"unexpected HTTP call for explicit images: {url}")

    conn = HarborConnector(
        registry_cfg("h", "harbor", {"url": "https://harbor.acme.io", "registry": "harbor.acme.io",
                                     "images": ["team/app:1.0", "harbor.acme.io/lib/base:3"]}),
        http=_no_http,
    )
    refs = {t.reference for t in conn.discover_images()}
    assert "harbor.acme.io/team/app:1.0" in refs
    assert "harbor.acme.io/lib/base:3" in refs  # host stripped if user included it
