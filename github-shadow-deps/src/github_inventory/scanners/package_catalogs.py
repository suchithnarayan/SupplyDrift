"""Package catalog scanners for Homebrew, Scoop, and WinGet manifests."""
from __future__ import annotations

import json
import re
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is a project dependency
    yaml = None  # type: ignore[assignment]

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner

_HOMEBREW_URL_RE = re.compile(r"^\s*url\s+['\"](?P<dep>https?://[^'\"]+)['\"]", re.MULTILINE)


class PackageCatalogScanner(BaseScanner):
    name = "package-catalogs"

    def register_rules(self) -> None:
        # Structured scanner; no broad regex rules.
        return None

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        if _is_test_fixture_catalog_path(target.rel_path):
            return []
        if target.file_type == "homebrew_formula":
            return _scan_homebrew_formula(target, content)
        if target.file_type == "scoop_manifest":
            return _scan_scoop_manifest(target, content)
        if target.file_type == "winget_manifest":
            return _scan_winget_manifest(target, content)
        return []


def _scan_homebrew_formula(target: FileTarget, content: str) -> list[Finding]:
    has_sha256 = re.search(
        r"^\s*sha256\s+['\"][a-f0-9]{32,}['\"]",
        content,
        re.MULTILINE | re.IGNORECASE,
    )
    severity = Severity.LOW if has_sha256 else Severity.MEDIUM
    findings: list[Finding] = []
    for match in _HOMEBREW_URL_RE.finditer(content):
        url = match.group("dep")
        findings.append(_make_finding(
            target=target,
            content=content,
            dep=url,
            matched=url,
            severity=severity,
            pattern_id="homebrew-formula-url",
            description=f"Homebrew formula references downloadable artifact: {url}",
        ))
    return _dedupe(findings)


def _scan_scoop_manifest(target: FileTarget, content: str) -> list[Finding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    has_hash = bool(_find_key_values(data, "hash"))
    severity = Severity.LOW if has_hash else Severity.MEDIUM
    return _find_url_findings(
        target=target,
        content=content,
        data=data,
        key="url",
        severity=severity,
        pattern_id="scoop-manifest-url",
        description_template="Scoop manifest references downloadable artifact: {dep}",
    )


def _scan_winget_manifest(target: FileTarget, content: str) -> list[Finding]:
    if yaml is None:
        return []
    try:
        data = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        return []
    has_hash = bool(_find_key_values(data, "InstallerSha256"))
    severity = Severity.LOW if has_hash else Severity.MEDIUM
    return _find_url_findings(
        target=target,
        content=content,
        data=data,
        key="InstallerUrl",
        severity=severity,
        pattern_id="winget-installer-url",
        description_template="WinGet manifest references installer artifact: {dep}",
    )


def _find_url_findings(
    *,
    target: FileTarget,
    content: str,
    data: Any,
    key: str,
    severity: Severity,
    pattern_id: str,
    description_template: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for url in _find_key_values(data, key):
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            findings.append(_make_finding(
                target=target,
                content=content,
                dep=url,
                matched=url,
                severity=severity,
                pattern_id=pattern_id,
                description=description_template.format(dep=url),
            ))
        elif isinstance(url, list):
            for item in url:
                if isinstance(item, str) and item.startswith(("http://", "https://")):
                    findings.append(_make_finding(
                        target=target,
                        content=content,
                        dep=item,
                        matched=item,
                        severity=severity,
                        pattern_id=pattern_id,
                        description=description_template.format(dep=item),
                    ))
    return _dedupe(findings)


def _find_key_values(value: Any, key: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            if child_key == key:
                found.append(child_value)
            found.extend(_find_key_values(child_value, key))
    elif isinstance(value, list):
        for child in value:
            found.extend(_find_key_values(child, key))
    return found


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
        category=Category.BINARY_DOWNLOAD,
        severity=severity,
        pattern_id=pattern_id,
        matched_text=matched[:200],
        extracted_dep=dep[:200],
        description=description,
        scanner_name=PackageCatalogScanner.name,
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


def _is_test_fixture_catalog_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").lower().split("/")
    has_test_path = any(part in {"test", "tests", "testing"} or part.endswith("tests") for part in parts[:-1])
    has_fixture_data = any(
        part in {
            "fixture",
            "fixtures",
            "__fixtures__",
            "resource",
            "resources",
            "snapshot",
            "snapshots",
            "testdata",
            "test-data",
        }
        for part in parts[:-1]
    )
    return has_test_path and has_fixture_data
