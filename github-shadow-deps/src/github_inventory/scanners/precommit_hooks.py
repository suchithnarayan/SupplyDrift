"""Pre-commit hook repository references in .pre-commit-config.yaml."""
from __future__ import annotations

import re

from github_inventory.models import Category, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class PrecommitHookScanner(BaseScanner):
    name = "precommit-hooks"

    def scan_file_content(self, target, content: str, lines: list[str]):
        findings = super().scan_file_content(target, content, lines)
        _normalize_precommit_repo_revisions(findings, lines)
        return _dedupe_findings_by_file_dependency(findings)

    def register_rules(self) -> None:
        # repo: https://github.com/org/repo (git-based hook source).
        # The 3rd-party repo URL is the actionable signal — a bare `rev:`
        # version string with no repo context isn't useful (a tag like
        # `v4.6.0` says nothing about who's hosting it). The previous
        # `precommit-mutable-rev` rule was removed because it fired on
        # every well-formed semver tag in every Python project.
        self.add_rule(PatternRule(
            pattern_id="precommit-repo",
            regex=re.compile(
                r"repo:\s*(?P<dep>https?://\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="Pre-commit hook pulls from external repo: {dep}",
            category=Category.PRECOMMIT_HOOK,
            file_types=["precommit_config"],
        ))


def _dedupe_findings_by_file_dependency(findings):
    deduped = []
    seen = set()
    for finding in findings:
        key = (finding.file_path, finding.pattern_id, finding.extracted_dep)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _normalize_precommit_repo_revisions(findings, lines: list[str]) -> None:
    for finding in findings:
        if finding.pattern_id != "precommit-repo":
            continue
        rev = _precommit_repo_rev(lines, finding.line_number)
        if not rev:
            continue
        dep = f"{finding.extracted_dep}@{rev}"
        finding.extracted_dep = dep
        finding.description = f"Pre-commit hook pulls from external repo: {dep}"


def _precommit_repo_rev(lines: list[str], repo_line_number: int) -> str:
    if repo_line_number < 1 or repo_line_number > len(lines):
        return ""
    for line in lines[repo_line_number:]:
        if re.match(r"^\s*-\s*repo:\s*", line, re.IGNORECASE):
            break
        match = re.match(r"^\s*rev:\s*(?P<rev>[^\s#]+)", line, re.IGNORECASE)
        if match:
            return match.group("rev").strip("'\"")
    return ""
