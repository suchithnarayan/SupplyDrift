"""Tests for the Harbor connector (Harbor v2 API discovery)."""
from __future__ import annotations

import base64
import json

import pytest
from conftest import registry_cfg

from image_scanner.connectors.base import ConnectorError
from image_scanner.connectors.harbor import (
    HarborConnector,
    _double_encode,
    _validate_public_url,
)


def make_source(url="https://harbor.acme.io", registry="harbor.acme.io", **filter_kwargs):
    return registry_cfg(
        "harbor",
        "harbor",
        {
            "url": url,
            "registry": registry,
            "auth": {"username": "robot$team-a+scan", "password": "s3cr3t"},
        },
        **filter_kwargs,
    )


class FakeHarbor:
    def __init__(self):
        self.calls: list[str] = []

    def __call__(self, url, headers):
        self.calls.append(url)
        expected = "Basic " + base64.b64encode(b"robot$team-a+scan:s3cr3t").decode()
        assert headers.get("Authorization") == expected
        if "/artifacts" in url:
            if "app/artifacts" in url:
                body = [{"digest": "sha256:app1", "push_time": "2026-05-20T00:00:00Z",
                         "tags": [{"name": "1.0"}, {"name": "latest"}]}]
            else:  # nested/svc
                body = [{"digest": "sha256:svc1", "push_time": "2026-05-21T00:00:00Z",
                         "tags": [{"name": "2.0"}]}]
            return 200, {}, json.dumps(body).encode()
        if "/repositories" in url:
            return 200, {}, json.dumps(
                [{"name": "team-a/app"}, {"name": "team-a/nested/svc"}]
            ).encode()
        if "/projects" in url:
            return 200, {}, json.dumps([{"name": "team-a"}, {"name": "other"}]).encode()
        return 404, {}, b"[]"


def test_double_encode_nested_repo():
    assert _double_encode("team/app") == "team%252Fapp"
    assert _double_encode("app") == "app"


def test_harbor_discovers_projects_repos_artifacts():
    conn = HarborConnector(make_source(projects=["team-*"]), http=FakeHarbor())
    targets = list(conn.discover_images())
    refs = {t.reference for t in targets}
    assert "harbor.acme.io/team-a/app:1.0@sha256:app1" in refs
    assert "harbor.acme.io/team-a/app:latest@sha256:app1" in refs
    assert "harbor.acme.io/team-a/nested/svc:2.0@sha256:svc1" in refs
    assert all(t.provider == "harbor" for t in targets)
    assert all(t.registry == "harbor.acme.io" for t in targets)


def test_harbor_nested_repo_is_double_encoded_in_request():
    hub = FakeHarbor()
    conn = HarborConnector(make_source(projects=["team-*"]), http=hub)
    list(conn.discover_images())
    assert any("nested%252Fsvc/artifacts" in url for url in hub.calls)


def test_harbor_project_filter_excludes_other():
    conn = HarborConnector(make_source(projects=["team-*"]), http=FakeHarbor())
    projects = {t.repository.split("/", 1)[0] for t in conn.discover_images()}
    assert projects == {"team-a"}


def test_harbor_pull_auth_embedded():
    conn = HarborConnector(make_source(projects=["team-*"]), http=FakeHarbor())
    target = next(iter(conn.discover_images()))
    assert target.auth is not None
    assert target.auth.username == "robot$team-a+scan" and target.auth.password == "s3cr3t"


def test_harbor_direct_pull_resolves_explicit_docker_config(tmp_path):
    config = tmp_path / "config.json"
    encoded = base64.b64encode(b"robot$scan:docker-secret").decode()
    config.write_text(
        json.dumps({"auths": {"harbor.acme.io": {"auth": encoded}}}),
        encoding="utf-8",
    )
    source = registry_cfg(
        "harbor",
        "harbor",
        {
            "url": "https://harbor.acme.io",
            "registry": "harbor.acme.io",
            "images": ["team/app:1"],
            "auth": {"provider": "docker", "config_path": str(config)},
        },
    )
    conn = HarborConnector(source, http=lambda *args: (500, {}, b""))

    auth = conn.registry_auth_for(None)

    assert auth and auth.username == "robot$scan"
    assert auth.password == "docker-secret"


# --- SSRF / credential-exfiltration guard (SD-04) --------------------------- #
# The robot Basic credential rides every request, so the tenant-controlled
# connection.url must be scheme- and host-validated. These hit the validation
# path directly (IP literals + scheme) — no DNS, no real network calls.
@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254",           # cloud metadata endpoint
        "http://169.254.169.254/latest/",   # metadata endpoint w/ path
        "http://10.0.0.5",                   # RFC1918 private
        "http://192.168.1.10:8080",          # RFC1918 private w/ port
        "https://127.0.0.1",                 # loopback (https not exempt)
        "https://169.254.169.254",           # metadata over https
        "http://1.2.3.4",                    # public IP over http (must be https)
        "ftp://harbor.acme.io",              # non-http(s) scheme
        "https:///no-host",                  # missing host
    ],
)
def test_validate_public_url_rejects_ssrf_targets(url):
    with pytest.raises(ConnectorError):
        _validate_public_url(url, where="test")


def test_validate_public_url_allows_https_and_loopback_http():
    # A loopback host over http is the sanctioned local-testing carve-out.
    _validate_public_url("http://127.0.0.1:8080", where="test")
    _validate_public_url("http://[::1]", where="test")


def test_harbor_rejects_private_url_at_construction():
    # Constructing with the real (default) transport must resolve + reject the
    # metadata endpoint before any HTTP request is issued.
    with pytest.raises(ConnectorError):
        HarborConnector(make_source(url="http://169.254.169.254", registry="169.254.169.254"))


def test_harbor_rejects_non_https_public_url_at_construction():
    with pytest.raises(ConnectorError):
        HarborConnector(make_source(url="ftp://harbor.acme.io"))


def test_harbor_accepts_https_public_url():
    # A normal https URL constructs fine with an injected transport (no network).
    conn = HarborConnector(make_source(url="https://harbor.example.com",
                                       registry="harbor.example.com"),
                           http=FakeHarbor())
    assert conn.url == "https://harbor.example.com"


def test_harbor_default_http_refuses_redirect():
    # A 3xx that would replay the Authorization header off-Harbor must raise.
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from image_scanner.connectors.harbor import _default_http

    class _Redirector(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()

        def log_message(self, *args):  # silence
            pass

    srv = HTTPServer(("127.0.0.1", 0), _Redirector)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(ConnectorError, match="redirect"):
            _default_http(
                f"http://127.0.0.1:{srv.server_address[1]}/api/v2.0/projects",
                {"Authorization": "Basic c2VjcmV0"},
            )
    finally:
        srv.shutdown()
