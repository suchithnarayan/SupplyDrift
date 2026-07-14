"""Devcontainer image and feature references in devcontainer.json."""
from __future__ import annotations

import re

from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class DevcontainerScanner(BaseScanner):
    name = "devcontainer"

    def scan_file_content(self, target, content: str, lines: list[str]):
        if _is_test_fixture_devcontainer_path(target.rel_path):
            return []
        findings = super().scan_file_content(target, content, lines)
        findings = [
            finding for finding in findings
            if not _is_jsonc_commented_reference(lines, finding.line_number, finding.extracted_dep)
        ]
        return _normalize_devcontainer_feature_findings(findings)

    def register_rules(self) -> None:
        # "image": "mcr.microsoft.com/devcontainers/base:ubuntu"
        self.add_rule(PatternRule(
            pattern_id="devcontainer-image",
            regex=re.compile(
                r'"image"\s*:\s*"(?P<dep>[^"]+)"',
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Devcontainer pulls container image: {dep}",
            category=Category.DEVCONTAINER,
            file_types=["devcontainer"],
        ))

        # "features": { "ghcr.io/devcontainers/features/node:1": {} }
        self.add_rule(PatternRule(
            pattern_id="devcontainer-feature",
            regex=re.compile(
                r'"(?P<dep>(?:ghcr\.io|mcr\.microsoft\.com|[\w.-]+\.[\w.-]+)/[\w./@:-]+)":\s*\{',
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Devcontainer feature (OCI artifact): {dep}",
            category=Category.DEVCONTAINER,
            file_types=["devcontainer"],
        ))


def _normalize_devcontainer_feature_findings(findings: list[Finding]) -> list[Finding]:
    normalized: list[Finding] = []
    for finding in findings:
        if finding.pattern_id != "devcontainer-feature" or not finding.extracted_dep.endswith(":"):
            normalized.append(finding)
            continue
        dep = finding.extracted_dep.rstrip(":")
        normalized.append(Finding(
            file_path=finding.file_path,
            line_number=finding.line_number,
            category=finding.category,
            severity=finding.severity,
            pattern_id=finding.pattern_id,
            matched_text=finding.matched_text,
            extracted_dep=dep,
            description=f"Devcontainer feature (OCI artifact): {dep}",
            scanner_name=finding.scanner_name,
            end_line=finding.end_line,
            analysis_source=finding.analysis_source,
            confidence=finding.confidence,
            enrichment=finding.enrichment,
        ))
    return normalized


def _is_jsonc_commented_reference(lines: list[str], line_number: int, dep: str) -> bool:
    if not dep or not (0 < line_number <= len(lines)):
        return False
    line = lines[line_number - 1]
    dep_index = line.find(dep)
    if dep_index == -1:
        return False
    prefix = line[:dep_index]
    if prefix.strip().startswith("//"):
        return True
    return prefix.rfind("/*") > prefix.rfind("*/")


def _is_test_fixture_devcontainer_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").lower().split("/")
    has_devcontainer_name = len(parts) >= 2 and parts[-2] == ".devcontainer" and parts[-1] == "devcontainer.json"
    if not has_devcontainer_name:
        return False
    has_test_path = any(part in {"test", "tests", "testing"} or part.endswith("tests") for part in parts[:-2])
    has_fixture_data = any(
        part in {"fixture", "fixtures", "__fixtures__", "resource", "resources", "testdata", "test-data"}
        for part in parts[:-2]
    )
    return has_test_path and has_fixture_data
