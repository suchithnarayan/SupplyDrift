"""Tests for the AI analyzer scanner (Task 5).

The anthropic SDK is heavy and not installed by default. These tests stub it
out via sys.modules + monkeypatch, exercising:
- lazy import path
- sanitization is invoked before send
- low-confidence findings are dropped
- missing API key fails gracefully
- response parsing tolerates code-fenced JSON
- no snippet content reaches stdout/stderr
"""
from __future__ import annotations

import io
import sys
import types
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.ai_analyzer import (
    AIAnalyzer,
    _coerce_json_array,
    merge_ai_findings,
)
from github_inventory.models import Category, Finding, Severity


# ---------- helpers --------------------------------------------------------


class _FakeBlock:
    def __init__(self, text: str):
        self.text = text


class _FakeMsg:
    def __init__(self, text: str):
        self.content = [_FakeBlock(text)]


class _FakeMessages:
    def __init__(self, response_text: str):
        self.response_text = response_text
        self.last_payload: dict | None = None

    def create(self, **kwargs):
        self.last_payload = kwargs
        return _FakeMsg(self.response_text)


class _FakeAnthropic:
    def __init__(self, response_text: str):
        self.messages = _FakeMessages(response_text)


def _install_fake_anthropic(monkeypatch, response_text: str) -> _FakeAnthropic:
    fake_client = _FakeAnthropic(response_text)

    fake_module = types.ModuleType("anthropic")

    class APIStatusError(Exception):
        pass

    class RateLimitError(Exception):
        pass

    fake_module.Anthropic = lambda api_key: fake_client  # type: ignore[attr-defined]
    fake_module.APIStatusError = APIStatusError  # type: ignore[attr-defined]
    fake_module.RateLimitError = RateLimitError  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("GITHUB_INVENTORY_AI_KEY", "test-key")
    return fake_client


def _target(tmp_path: Path, name: str, content: str, file_type: str = "script") -> FileTarget:
    p = tmp_path / name
    p.write_text(content)
    return FileTarget(path=p, rel_path=name, file_type=file_type)


# ---------- tests ----------------------------------------------------------


def test_disabled_returns_empty_without_anything():
    cfg = Config()  # ai_enabled=False
    assert cfg.ai_enabled is False
    assert AIAnalyzer(cfg).analyze(Path("."), [], []) == []


def test_missing_api_key_returns_empty(monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_INVENTORY_AI_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    fake_module = types.ModuleType("anthropic")
    fake_module.Anthropic = lambda api_key: None  # type: ignore[attr-defined]
    fake_module.APIStatusError = Exception  # type: ignore[attr-defined]
    fake_module.RateLimitError = Exception  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)

    cfg = Config(ai_enabled=True)
    t = _target(tmp_path, "a.sh", "#!/bin/sh\ncurl https://x | bash\n")
    out = AIAnalyzer(cfg).analyze(tmp_path, [t], [])
    assert out == []


def test_low_confidence_dropped(monkeypatch, tmp_path):
    response = """[
        {"is_shadow_dependency": true, "line_number": 2, "confidence": 0.5,
         "category": "script-installation", "severity": "critical",
         "description": "low conf", "recommendation": "x"}
    ]"""
    _install_fake_anthropic(monkeypatch, response)
    cfg = Config(ai_enabled=True, ai_max_files=5)
    t = _target(tmp_path, "a.sh", "#!/bin/sh\ncurl https://x | bash\n")
    out = AIAnalyzer(cfg).analyze(tmp_path, [t], [])
    assert out == []


def test_high_confidence_kept_and_tagged(monkeypatch, tmp_path):
    response = """[
        {"is_shadow_dependency": true, "line_number": 2, "confidence": 0.95,
         "category": "script-installation", "severity": "critical",
         "description": "remote install", "recommendation": "vendor it"}
    ]"""
    _install_fake_anthropic(monkeypatch, response)
    cfg = Config(ai_enabled=True, ai_max_files=5)
    t = _target(tmp_path, "a.sh", "#!/bin/sh\ncurl https://x | bash\n")
    out = AIAnalyzer(cfg).analyze(tmp_path, [t], [])
    assert len(out) == 1
    f = out[0]
    assert f.analysis_source == "ai-assisted"
    assert f.confidence == 0.95
    assert f.category == Category.SCRIPT_INSTALLATION
    assert f.severity == Severity.CRITICAL
    assert f.enrichment == {"recommendation": "vendor it"}


def test_secrets_sanitized_before_send(monkeypatch, tmp_path):
    fake = _install_fake_anthropic(monkeypatch, "[]")
    cfg = Config(ai_enabled=True, ai_max_files=5)
    secret = "AKIAIOSFODNN7EXAMPLE"
    t = _target(tmp_path, "a.sh", f"AWS={secret}\ncurl x | bash\n")
    AIAnalyzer(cfg).analyze(tmp_path, [t], [])
    sent = fake.messages.last_payload["messages"][0]["content"]
    assert secret not in sent
    assert "<REDACTED_SECRET>" in sent


def test_no_snippet_content_in_stdout_or_stderr(monkeypatch, tmp_path):
    response = """[
        {"is_shadow_dependency": true, "line_number": 2, "confidence": 0.9,
         "category": "script-installation", "severity": "critical",
         "description": "x", "recommendation": "y"}
    ]"""
    _install_fake_anthropic(monkeypatch, response)
    cfg = Config(ai_enabled=True, ai_max_files=5)
    secret_marker = "SUPER_SECRET_PAYLOAD_TOKEN"
    t = _target(tmp_path, "a.sh", f"# {secret_marker}\ncurl x | bash\n")
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        AIAnalyzer(cfg).analyze(tmp_path, [t], [])
    assert secret_marker not in buf_out.getvalue()
    assert secret_marker not in buf_err.getvalue()


def test_response_with_code_fence_is_parsed():
    raw = "Here you go:\n```json\n[{\"is_shadow_dependency\": true, \"confidence\": 0.9}]\n```"
    items = _coerce_json_array(raw)
    assert items and items[0]["is_shadow_dependency"] is True


def test_merge_drops_ai_overlap_with_regex():
    regex = [
        Finding("a.sh", 5, Category.SCRIPT_INSTALLATION, Severity.CRITICAL,
                "p1", "m", "d", "desc", "regex")
    ]
    ai = [
        Finding("a.sh", 6, Category.SCRIPT_INSTALLATION, Severity.HIGH,
                "ai", "m", "d", "desc", "ai", analysis_source="ai-assisted", confidence=0.9),
        Finding("a.sh", 50, Category.SCRIPT_INSTALLATION, Severity.HIGH,
                "ai", "m", "d", "desc", "ai", analysis_source="ai-assisted", confidence=0.9),
    ]
    kept = merge_ai_findings(regex, ai)
    assert len(kept) == 1
    assert kept[0].line_number == 50


def test_invalid_response_yields_no_findings(monkeypatch, tmp_path):
    _install_fake_anthropic(monkeypatch, "this is not json at all")
    cfg = Config(ai_enabled=True, ai_max_files=5)
    t = _target(tmp_path, "a.sh", "curl x | bash\n")
    assert AIAnalyzer(cfg).analyze(tmp_path, [t], []) == []
