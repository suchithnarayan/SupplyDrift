"""Streaming push: each repo is pushed as soon as it finishes scanning, so a
crash/failure mid-run still persists everything scanned up to that point."""
from __future__ import annotations

import contextlib

import github_inventory.sync.pipeline as pipeline
from github_inventory.sync.config import Config, PlatformConfig, ScannerConfig
from github_inventory.sync.connector import RepoTarget


def _repo(name: str) -> RepoTarget:
    return RepoTarget(full_name=f"org/{name}", owner="org", repo=name,
                      clone_url=f"https://github.com/org/{name}.git", html_url="")


def _cfg(**scanner) -> Config:
    return Config(version=1, platform=PlatformConfig(url="http://platform", push=True),
                  scanner=ScannerConfig(concurrency=1, scan_sbom=False, **scanner), sources=[])


@contextlib.contextmanager
def _fake_resolve(clone_url, token="", timeout=0):
    yield "/tmp"


class _FakeEngine:
    def __init__(self, *a, **k):
        pass

    def run(self):
        return object()


def _wire(monkeypatch, repos, push_repo):
    monkeypatch.setattr(pipeline, "discover", lambda cfg, sf=None: ([("src", r) for r in repos], [], {"src": len(repos)}))
    monkeypatch.setattr(pipeline, "resolve_repo", _fake_resolve)
    monkeypatch.setattr(pipeline, "ScanEngine", _FakeEngine)
    monkeypatch.setattr(pipeline, "push_repo", push_repo)


def test_partial_progress_on_scan_failure(monkeypatch):
    repos = [_repo("r0"), _repo("r1"), _repo("r2")]
    pushed: list[str] = []
    _wire(monkeypatch, repos, lambda url, payload: pushed.append(payload["assets"][0]["ref"]))

    # r1 fails to build/scan mid-run; r0 and r2 must still be pushed.
    def build(repo, scan_result, source, cyclonedx=None):
        if repo.repo == "r1":
            raise RuntimeError("scan blew up")
        return {"assets": [{"ref": repo.repo}], "scan_metadata": {"component_count": 2, "finding_count": 1}}
    monkeypatch.setattr(pipeline, "build_payload", build)

    result = pipeline.run(_cfg())

    assert sorted(pushed) == ["r0", "r2"]          # the failure did NOT block the others
    assert result.pushed == 2
    assert any("r1" in e for e in result.errors)
    # payloads released after a successful push (memory stays bounded for hundreds of repos)
    assert all(r.payload is None for r in result.results if r.ok)


def test_push_failure_is_recorded_not_fatal(monkeypatch):
    repos = [_repo("r0"), _repo("r1")]

    def flaky(url, payload):
        if payload["assets"][0]["ref"] == "r0":
            raise RuntimeError("platform down")
    _wire(monkeypatch, repos, flaky)
    monkeypatch.setattr(pipeline, "build_payload",
                        lambda repo, sr, src, cyclonedx=None: {"assets": [{"ref": repo.repo}],
                                                               "scan_metadata": {"component_count": 1, "finding_count": 0}})

    result = pipeline.run(_cfg())

    assert result.pushed == 1                       # r1 pushed even though r0's push failed
    assert any("push" in e and "r0" in e for e in result.errors)


def test_no_push_keeps_payloads(monkeypatch):
    repos = [_repo("r0"), _repo("r1")]
    pushed: list[str] = []
    _wire(monkeypatch, repos, lambda url, payload: pushed.append(payload["assets"][0]["ref"]))
    monkeypatch.setattr(pipeline, "build_payload",
                        lambda repo, sr, src, cyclonedx=None: {"assets": [{"ref": repo.repo}],
                                                               "scan_metadata": {"component_count": 1, "finding_count": 0}})

    result = pipeline.run(_cfg(), push=False)

    assert pushed == [] and result.pushed == 0
    assert all(r.payload is not None for r in result.results if r.ok)  # kept for --format json


def test_inventory_refresh_pushes_discovery_without_cloning(monkeypatch):
    repos = [_repo("r0"), _repo("r1")]
    pushed: list[dict] = []
    monkeypatch.setattr(
        pipeline, "discover",
        lambda cfg, sf=None: ([("src", r) for r in repos], [], {"src": len(repos)}),
    )
    monkeypatch.setattr(
        pipeline, "resolve_repo",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("refresh must not clone")),
    )
    monkeypatch.setattr(pipeline, "push_repo", lambda url, payload: pushed.append(payload))

    result = pipeline.run(_cfg(), inventory_only=True)

    assert result.pushed == 2 and not result.errors
    assert result.summary()["scanned_ok"] == 0
    assert all(p["discovery_only"] is True for p in pushed)
    assert all(p["components"] == [] and p["findings"] == [] for p in pushed)
