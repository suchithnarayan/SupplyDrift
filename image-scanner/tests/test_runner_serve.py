"""Runner --serve mode: claim a queued job, run it for that source, report status."""
from __future__ import annotations

import logging
import types

from image_scanner import cli

LOG = logging.getLogger("test")


def _fake_config():
    # config.platform.url starts as a public address the runner must override.
    return types.SimpleNamespace(platform=types.SimpleNamespace(url="http://public-browser-url:8765"))


class _Result:
    errors: list = []

    def summary(self):
        return {"discovered": 2, "scanned_ok": 2, "scanned_failed": 0, "pushed": 2,
                "by_source": {}, "total_components": 10, "total_vulnerabilities": 3, "errors": []}


def test_claim_and_run_reports_success(monkeypatch):
    posts = []

    def fake_post(url, body):
        posts.append((url, body))
        return {"id": "run-1", "source_name": "My Dockerhub"} if url.endswith("/claim") else {}

    monkeypatch.setattr(cli, "load_config_from_url", lambda url: _fake_config())
    captured = {}

    def fake_run(config, sources_filter=None, push=True, inventory_only=False):
        captured["sources_filter"] = sources_filter
        captured["push"] = push
        captured["inventory_only"] = inventory_only
        captured["platform_url"] = config.platform.url
        return _Result()

    worked = cli._claim_and_run("http://p", "http://p/api/scanner/config", "runner-1",
                                post=fake_post, run_pipeline=fake_run, log=LOG)
    assert worked is True
    assert captured["sources_filter"] == {"My Dockerhub"} and captured["push"] is True
    assert captured["inventory_only"] is False
    # the runner pushes back to the platform it claimed from, not the config's public URL
    assert captured["platform_url"] == "http://p"
    complete = next(b for u, b in posts if u.endswith("/complete"))
    assert complete["status"] == "succeeded" and complete["summary"]["scanned_ok"] == 2
    assert any(u.endswith("/api/scan/runs/run-1/complete") for u, _ in posts)


def test_claim_and_run_empty_queue():
    worked = cli._claim_and_run("http://p", "http://p/api/scanner/config", "r",
                                post=lambda u, b: None, run_pipeline=lambda *a, **k: None, log=LOG)
    assert worked is False


def test_claim_and_run_refresh_uses_inventory_only(monkeypatch):
    posts = []

    def fake_post(url, body):
        posts.append((url, body))
        if url.endswith("/claim"):
            return {"id": "run-refresh", "source_name": "K8s", "summary": {"action": "refresh"}}
        return {}

    monkeypatch.setattr(cli, "load_config_from_url", lambda url: _fake_config())
    captured = {}

    def fake_run(config, sources_filter=None, push=True, inventory_only=False):
        captured["inventory_only"] = inventory_only
        return _Result()

    worked = cli._claim_and_run("http://p", "http://p/api/scanner/config", "runner-1",
                                post=fake_post, run_pipeline=fake_run, log=LOG)
    assert worked is True
    assert captured["inventory_only"] is True
    complete = next(b for u, b in posts if u.endswith("/complete"))
    assert complete["summary"]["action"] == "refresh"


def test_claim_and_run_reports_failure(monkeypatch):
    posts = []

    def fake_post(url, body):
        posts.append((url, body))
        return {"id": "run-2", "source_name": "DH"} if url.endswith("/claim") else {}

    monkeypatch.setattr(cli, "load_config_from_url", lambda url: _fake_config())

    def boom(config, sources_filter=None, push=True, inventory_only=False):
        raise RuntimeError("scan exploded")

    worked = cli._claim_and_run("http://p", "http://p/api/scanner/config", "r",
                                post=fake_post, run_pipeline=boom, log=LOG)
    assert worked is True
    complete = next(b for u, b in posts if u.endswith("/complete"))
    assert complete["status"] == "failed" and "exploded" in complete["error"]


def test_claim_and_run_reports_discovery_error_as_failure(monkeypatch):
    posts = []

    def fake_post(url, body):
        posts.append((url, body))
        return {"id": "run-3", "source_name": "Missing"} if url.endswith("/claim") else {}

    monkeypatch.setattr(cli, "load_config_from_url", lambda url: _fake_config())

    class DiscoveryErrorResult:
        errors = ["[Missing] registry returned HTTP 400"]

        def summary(self):
            return {
                "discovered": 0, "scanned_ok": 0, "scanned_failed": 0,
                "pushed": 0, "by_source": {}, "total_components": 0,
                "total_vulnerabilities": 0, "errors": self.errors,
            }

    worked = cli._claim_and_run(
        "http://p", "http://p/api/scanner/config", "r",
        post=fake_post, run_pipeline=lambda *a, **k: DiscoveryErrorResult(), log=LOG,
    )
    assert worked is True
    complete = next(b for u, b in posts if u.endswith("/complete"))
    assert complete["status"] == "failed"
    assert "HTTP 400" in complete["error"]
