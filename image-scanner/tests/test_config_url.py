"""Tests for fetching the scanner config from the platform (--config-url)."""
from __future__ import annotations

import json

import pytest

from image_scanner.config import load_config_from_url

PLATFORM_CONFIG = {
    "version": 2,
    "platform": {"url": "http://platform:8765", "push": True},
    "registries": [
        {
            "name": "ghcr-acme",
            "type": "ghcr",
            "connection": {"owner": "acme", "auth": {"provider": "env", "token_env": "GH_PAT"}},
            "scan": {"repositories": ["acme/*"]},
        }
    ],
    "services": [
        {"name": "eks-prod", "type": "eks", "connection": {"aws_auth": {"regions": ["us-east-1"]}}}
    ],
}


def test_load_config_from_url_parses_platform_document():
    seen = {}

    def fetcher(url: str) -> str:
        seen["url"] = url
        return json.dumps(PLATFORM_CONFIG)

    cfg = load_config_from_url("http://platform:8765/api/scanner/config", fetcher=fetcher)
    assert seen["url"].endswith("/api/scanner/config")
    assert [r.type for r in cfg.registries] == ["ghcr"]
    assert cfg.source("ghcr-acme").connection["owner"] == "acme"
    assert [s.type for s in cfg.services] == ["eks"]
    assert cfg.services[0].aws_session.region_list() == ["us-east-1"]


def test_load_config_from_url_rejects_bad_json():
    with pytest.raises(RuntimeError, match="not valid JSON"):
        load_config_from_url("http://x/api/scanner/config", fetcher=lambda url: "<html>nope")


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "ftp://host/cfg", "gopher://host", "jar:file:///x"],
)
def test_load_config_from_url_rejects_non_http_scheme(url):
    # With the default fetcher, only http(s) may be dereferenced (no file://, etc.).
    with pytest.raises(RuntimeError, match="http"):
        load_config_from_url(url)
