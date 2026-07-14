"""Streaming push: each image is pushed as soon as it finishes scanning, so a
crash/failure mid-run still persists everything scanned up to that point."""
from __future__ import annotations

import image_scanner.pipeline as pipeline
from image_scanner.config import Config, PlatformConfig, ScannerConfig
from image_scanner.models import ImageTarget


class _Res:
    def __init__(self, target, ok=True):
        self.target = target
        self._ok = ok
        self.component_count = 3
        self.vuln_count = 1
        self.vuln_error = ""
        self.error = "" if ok else "scan failed"

    @property
    def ok(self):
        return self._ok


class _Scanner:
    def __init__(self, extractor, vuln_scanner=None):
        self.vuln_scanner = vuln_scanner

    def scan(self, target):
        return _Res(target, ok=(target.repository != "bad"))


class _Extractor:
    name = "syft"

    def available(self):
        return True


def _target(repo):
    t = ImageTarget(reference=f"reg/{repo}:t", registry="reg", repository=repo, tag="t", source="src")
    t.auth = object()  # skip the auth-resolution step
    return t


def _cfg(**scanner):
    return Config(version=1, platform=PlatformConfig(url="http://platform", push=True),
                  scanner=ScannerConfig(concurrency=1, **scanner), registries=[], services=[])


def _wire(monkeypatch, targets, push_image):
    monkeypatch.setattr(pipeline, "discover", lambda cfg, sf=None: ([(object(), t) for t in targets], [], {"src": len(targets)}, []))
    monkeypatch.setattr(pipeline, "build_extractor", lambda sc: _Extractor())
    monkeypatch.setattr(pipeline, "build_vuln_scanner", lambda sc: None)
    monkeypatch.setattr(pipeline, "ImageScanner", _Scanner)
    monkeypatch.setattr(pipeline, "build_platform_payload", lambda res: {"ref": res.target.repository})
    monkeypatch.setattr(pipeline, "push_image", push_image)


def test_image_streams_push_partial_progress(monkeypatch):
    targets = [_target("a"), _target("bad"), _target("c")]
    pushed: list[str] = []
    _wire(monkeypatch, targets, lambda url, payload: pushed.append(payload["ref"]))

    result = pipeline.run(_cfg())

    assert sorted(pushed) == ["a", "c"]   # the failed 'bad' did not block the others
    assert result.pushed == 2
    assert any("scan failed" in e for e in result.errors)   # the failure was recorded


def test_image_push_failure_recorded(monkeypatch):
    targets = [_target("a"), _target("b")]

    def flaky(url, payload):
        if payload["ref"] == "a":
            raise RuntimeError("platform down")
    _wire(monkeypatch, targets, flaky)

    result = pipeline.run(_cfg())

    assert result.pushed == 1   # 'b' pushed even though 'a' push failed
    assert any("push" in e for e in result.errors)
