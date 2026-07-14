"""Agent plugin marketplace and manifest scanner.

Claude, Codex, Cursor, and similar coding-agent plugin manifests can pull
plugin content from external repositories. Those sources are executable agent
capability surface, but they are not visible to package-manifest SCA.
"""
from __future__ import annotations

import json
import re
from typing import Any

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner

_REMOTE_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_MUTABLE_REF_RE = re.compile(r"^(?:main|master|develop|dev|latest|edge|nightly|canary|next|alpha|beta)$", re.IGNORECASE)


class AgentPluginScanner(BaseScanner):
    name = "agent-plugins"

    def register_rules(self) -> None:
        # Structured JSON scanner; no regex rules needed.
        return None

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        if target.file_type != "agent_plugin":
            return []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for source in _plugin_sources(data):
            finding = _finding_for_source(target, content, source)
            if finding:
                findings.append(finding)
        return _dedupe(findings)


def _plugin_sources(value: Any) -> list[Any]:
    sources: list[Any] = []
    if isinstance(value, dict):
        if "source" in value:
            sources.append(value["source"])
        for child in value.values():
            sources.extend(_plugin_sources(child))
    elif isinstance(value, list):
        for child in value:
            sources.extend(_plugin_sources(child))
    return sources


def _finding_for_source(target: FileTarget, content: str, source: Any) -> Finding | None:
    if isinstance(source, str):
        if not _REMOTE_URL_RE.match(source):
            return None
        return _make_finding(
            target=target,
            content=content,
            dep=source,
            matched=source,
            severity=Severity.CRITICAL,
            pattern_id="agent-plugin-source-url-unpinned",
            description=f"Agent plugin manifest references external source without a pinned SHA: {source}",
        )

    if not isinstance(source, dict):
        return None

    url = source.get("url")
    if not isinstance(url, str) or not _REMOTE_URL_RE.match(url):
        return None

    sha = source.get("sha")
    ref = source.get("ref")
    has_sha = isinstance(sha, str) and bool(sha.strip())
    mutable_ref = isinstance(ref, str) and bool(_MUTABLE_REF_RE.match(ref.strip()))

    if not has_sha:
        return _make_finding(
            target=target,
            content=content,
            dep=url,
            matched=url,
            severity=Severity.CRITICAL,
            pattern_id="agent-plugin-source-url-unpinned",
            description=f"Agent plugin manifest references external source without a pinned SHA: {url}",
        )

    severity = Severity.MEDIUM if mutable_ref else Severity.HIGH
    pattern_id = "agent-plugin-source-mutable-ref" if mutable_ref else "agent-plugin-source-url"
    description = (
        f"Agent plugin manifest references external source pinned by SHA: {url}"
        if not mutable_ref
        else f"Agent plugin manifest references external source with mutable ref and SHA: {url}"
    )
    return _make_finding(
        target=target,
        content=content,
        dep=url,
        matched=url,
        severity=severity,
        pattern_id=pattern_id,
        description=description,
    )


def _make_finding(
    *,
    target: FileTarget,
    content: str,
    dep: str,
    matched: str,
    severity: Severity,
    pattern_id: str,
    description: str,
) -> Finding:
    return Finding(
        file_path=target.rel_path,
        line_number=_line_number(content, matched),
        category=Category.AGENT_PLUGIN,
        severity=severity,
        pattern_id=pattern_id,
        matched_text=matched[:200],
        extracted_dep=dep[:200],
        description=description,
        scanner_name=AgentPluginScanner.name,
    )


def _line_number(content: str, token: str) -> int:
    escaped = json.dumps(token)
    idx = content.find(escaped)
    if idx == -1:
        idx = content.find(token)
    return content[:idx].count("\n") + 1 if idx >= 0 else 1


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.file_path, finding.line_number, finding.pattern_id, finding.extracted_dep)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    return deduped
