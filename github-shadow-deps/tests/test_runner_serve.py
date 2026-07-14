"""github runner --serve: claim a queued job, run it for that source, report status."""
from __future__ import annotations

import logging
import types

from github_inventory.sync import cli

LOG = logging.getLogger("test")


def _fake_config():
    return types.SimpleNamespace(platform=types.SimpleNamespace(url="http://public-browser-url:8765"))


class _Result:
    errors: list = []

    def summary(self):
        return {"discovered": 3, "scanned_ok": 3, "scanned_failed": 0, "pushed": 3,
                "by_source": {}, "total_components": 40, "total_findings": 12, "errors": []}


def test_claim_and_run_github(monkeypatch):
    posts = []

    def fake_post(url, body):
        posts.append((url, body))
        return {"id": "run-1", "source_name": "My Repos"} if url.endswith("/claim") else {}

    monkeypatch.setattr(cli, "load_config_from_url", lambda url: _fake_config())
    captured = {}

    def fake_run(config, sources_filter=None, push=True, inventory_only=False):
        captured["sf"] = sources_filter
        captured["platform_url"] = config.platform.url
        captured["inventory_only"] = inventory_only
        return _Result()

    worked = cli._claim_and_run("http://p", "http://p/api/scanner/config", "gh-runner",
                                post=fake_post, run_pipeline=fake_run, log=LOG)
    assert worked is True
    # the claim asked for github jobs, and the run was scoped to the job's source
    assert posts[0][1]["job_type"] == "github" and captured["sf"] == {"My Repos"}
    assert captured["inventory_only"] is False
    # the runner pushes back to the platform it claimed from, not the config's public URL
    assert captured["platform_url"] == "http://p"
    complete = next(b for u, b in posts if u.endswith("/complete"))
    assert complete["status"] == "succeeded" and complete["summary"]["scanned_ok"] == 3


def test_claim_empty_queue():
    assert cli._claim_and_run("http://p", "http://p/cfg", "r",
                              post=lambda u, b: None, run_pipeline=lambda *a, **k: None, log=LOG) is False


def test_claim_and_run_refresh_uses_inventory_only(monkeypatch):
    posts = []

    def fake_post(url, body):
        posts.append((url, body))
        if url.endswith("/claim"):
            return {"id": "run-refresh", "source_name": "Repos", "summary": {"action": "refresh"}}
        return {}

    monkeypatch.setattr(cli, "load_config_from_url", lambda url: _fake_config())
    captured = {}

    def fake_run(config, sources_filter=None, push=True, inventory_only=False):
        captured["inventory_only"] = inventory_only
        return _Result()

    assert cli._claim_and_run(
        "http://p", "http://p/api/scanner/config", "gh-runner",
        post=fake_post, run_pipeline=fake_run, log=LOG,
    ) is True
    assert captured["inventory_only"] is True
    complete = next(b for u, b in posts if u.endswith("/complete"))
    assert complete["status"] == "succeeded"
    assert complete["summary"]["action"] == "refresh"


def test_claim_and_run_reports_discovery_error_as_failure(monkeypatch):
    posts = []

    def fake_post(url, body):
        posts.append((url, body))
        return {"id": "run-2", "source_name": "Missing"} if url.endswith("/claim") else {}

    monkeypatch.setattr(cli, "load_config_from_url", lambda url: _fake_config())

    class DiscoveryErrorResult:
        errors = ["[Missing] GitHub returned HTTP 404"]

        def summary(self):
            return {
                "discovered": 0, "scanned_ok": 0, "scanned_failed": 0,
                "pushed": 0, "by_source": {}, "total_components": 0,
                "total_findings": 0, "errors": self.errors,
            }

    worked = cli._claim_and_run(
        "http://p", "http://p/api/scanner/config", "gh-runner",
        post=fake_post, run_pipeline=lambda *a, **k: DiscoveryErrorResult(), log=LOG,
    )
    assert worked is True
    complete = next(b for u, b in posts if u.endswith("/complete"))
    assert complete["status"] == "failed"
    assert "HTTP 404" in complete["error"]
