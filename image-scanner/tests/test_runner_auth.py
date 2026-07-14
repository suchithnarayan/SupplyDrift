"""Runner bearer-token resolution: env override -> shared-volume file -> none."""
from __future__ import annotations

from image_scanner import config


def test_auth_headers_from_env(monkeypatch):
    monkeypatch.setenv("SUPPLYDRIFT_RUNNER_TOKEN", "tok123")
    assert config.auth_headers() == {"Authorization": "Bearer tok123"}


def test_auth_headers_from_file(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPPLYDRIFT_RUNNER_TOKEN", raising=False)
    f = tmp_path / "runner.token"
    f.write_text("filetok\n")
    monkeypatch.setenv("SUPPLYDRIFT_RUNNER_TOKEN_FILE", str(f))
    assert config.auth_headers() == {"Authorization": "Bearer filetok"}


def test_auth_headers_none(monkeypatch, tmp_path):
    monkeypatch.delenv("SUPPLYDRIFT_RUNNER_TOKEN", raising=False)
    monkeypatch.setenv("SUPPLYDRIFT_RUNNER_TOKEN_FILE", str(tmp_path / "missing"))
    assert config.auth_headers() == {}
