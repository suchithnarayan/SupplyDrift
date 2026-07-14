"""Tests for the GitHub sync config (file + platform feed)."""
from __future__ import annotations

import json

import pytest

from github_inventory.sync.config import load_config_from_url, parse_config


def test_parse_file_sources():
    cfg = parse_config({
        "version": 1,
        "platform": {"url": "http://p:8765", "push": False},
        "sources": [
            {"name": "org", "type": "github", "connection": {"owner": "acme"}, "scan": {"repositories": ["a*"]}},
            {"name": "pub", "type": "github", "connection": {"repositories": ["x/y"]}},
        ],
    })
    assert cfg.platform.url == "http://p:8765" and cfg.platform.push is False
    assert [s.name for s in cfg.sources] == ["org", "pub"]
    assert cfg.source("org").filters.repositories == ["a*"]
    assert cfg.source("pub").connection["repositories"] == ["x/y"]


def test_platform_feed_github_array():
    # The platform's /api/scanner/config returns a `github:` array.
    cfg = parse_config({
        "version": 2,
        "registries": [],
        "services": [],
        "github": [{"id": "connector-1", "name": "acme", "type": "github", "connection": {"owner": "acme"}}],
    })
    assert [s.name for s in cfg.sources] == ["acme"]
    assert cfg.source("acme").source_id == "connector-1"


def test_auth_optional():
    cfg = parse_config({"sources": [{"name": "pub", "type": "github", "connection": {"owner": "acme"}}]})
    assert "auth" not in cfg.source("pub").connection


def test_unknown_type_rejected():
    with pytest.raises(ValueError, match="unknown type"):
        parse_config({"sources": [{"name": "x", "type": "gitlab", "connection": {}}]})


def test_duplicate_names_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        parse_config({"sources": [
            {"name": "dup", "type": "github", "connection": {"owner": "a"}},
            {"name": "dup", "type": "github", "connection": {"owner": "b"}},
        ]})


def test_load_config_from_url():
    doc = {"version": 2, "github": [{"name": "acme", "type": "github", "connection": {"owner": "acme"}}]}
    cfg = load_config_from_url("http://p/api/scanner/config", fetcher=lambda url: json.dumps(doc))
    assert cfg.source("acme").connection["owner"] == "acme"


def test_load_config_from_url_rejects_non_http_schemes():
    # No fetcher injected -> the default urllib path must refuse non-http(s)
    # schemes before any request is made (mirrors the image-scanner check).
    for bad in ("file:///etc/passwd", "ftp://host/config", "gopher://host/1", "/etc/config.json"):
        with pytest.raises(RuntimeError, match="http"):
            load_config_from_url(bad)
