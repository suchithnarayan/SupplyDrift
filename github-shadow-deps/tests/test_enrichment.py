"""Tests for the enrichment client (Task 7)."""
from __future__ import annotations

import sys
import types

from github_inventory.config import Config
from github_inventory.enrichment import EnrichmentClient
from github_inventory.models import Category, Finding, Severity


class _FakeBlock:
    def __init__(self, text: str):
        self.text = text


class _FakeMsg:
    def __init__(self, text: str):
        self.content = [_FakeBlock(text)]


class _FakeMessages:
    def __init__(self, response_text: str):
        self.response_text = response_text
        self.last_payload = None
        self.call_count = 0

    def create(self, **kwargs):
        self.call_count += 1
        self.last_payload = kwargs
        return _FakeMsg(self.response_text)


class _FakeAnthropic:
    def __init__(self, text: str):
        self.messages = _FakeMessages(text)


def _install_fake(monkeypatch, response_text: str) -> _FakeAnthropic:
    fake_client = _FakeAnthropic(response_text)
    fake_module = types.ModuleType("anthropic")
    fake_module.Anthropic = lambda api_key: fake_client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    return fake_client


def _f(dep: str) -> Finding:
    return Finding(
        file_path="x.yml",
        line_number=1,
        category=Category.CICD_TOOL,
        severity=Severity.HIGH,
        pattern_id="p",
        matched_text="m",
        extracted_dep=dep,
        description="d",
        scanner_name="t",
    )


def test_disabled_does_nothing(monkeypatch):
    cfg = Config(ai_enabled=False, enrich_enabled=True)
    findings = [_f("actions/checkout@v4")]
    EnrichmentClient(cfg).enrich(findings)
    assert findings[0].enrichment is None


def test_batch_groups_by_extracted_dep(monkeypatch):
    response = '[{"summary": "Checkout action", "risks": "tag-pinned", "recommendation": "pin to SHA"}]'
    fake = _install_fake(monkeypatch, response)
    cfg = Config(ai_enabled=True, enrich_enabled=True)
    # Three findings, all the same dep — should be ONE call.
    findings = [_f("actions/checkout@v4") for _ in range(3)]
    EnrichmentClient(cfg).enrich(findings)
    assert fake.messages.call_count == 1
    for f in findings:
        assert f.enrichment is not None
        assert f.enrichment["recommendation"] == "pin to SHA"


def test_unknown_dep_returns_no_enrichment(monkeypatch):
    response = '[{"summary": "", "risks": "", "recommendation": ""}]'
    _install_fake(monkeypatch, response)
    cfg = Config(ai_enabled=True, enrich_enabled=True)
    findings = [_f("totally-unknown-thing")]
    EnrichmentClient(cfg).enrich(findings)
    assert findings[0].enrichment is None


def test_findings_without_dep_are_skipped(monkeypatch):
    fake = _install_fake(monkeypatch, "[]")
    cfg = Config(ai_enabled=True, enrich_enabled=True)
    f = _f("")  # empty extracted_dep
    EnrichmentClient(cfg).enrich([f])
    assert fake.messages.call_count == 0
    assert f.enrichment is None


def test_credential_is_redacted_before_enrichment_request(monkeypatch):
    canary = "supplydrift_enrichment_canary_19fe44"
    fake = _install_fake(
        monkeypatch,
        '[{"summary": "registry", "risks": "", "recommendation": "rotate"}]',
    )
    cfg = Config(ai_enabled=True, enrich_enabled=True)
    finding = _f(f"https://user:{canary}@registry.example/pkg?token={canary}")

    EnrichmentClient(cfg).enrich([finding])

    payload = fake.messages.last_payload
    assert payload is not None
    assert canary not in repr(payload)
    assert "[REDACTED]" in repr(payload)
