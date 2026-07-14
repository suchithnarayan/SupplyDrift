"""Tests for PrecommitHookScanner."""
from __future__ import annotations

import tempfile
from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.precommit_hooks import PrecommitHookScanner


def scan(content: str):
    scanner = PrecommitHookScanner(Config())
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        p = Path(f.name)
    target = FileTarget(path=p, rel_path=".pre-commit-config.yaml", file_type="precommit_config")
    return scanner.scan_file(target)


def test_dedupes_repeated_repo_url_in_same_file():
    findings = scan(
        "repos:\n"
        "  - repo: https://github.com/astral-sh/uv-pre-commit\n"
        "    rev: 0.5.26\n"
        "    hooks:\n"
        "      - id: uv-lock\n"
        "  - repo: https://github.com/astral-sh/uv-pre-commit\n"
        "    rev: 0.5.26\n"
        "    hooks:\n"
        "      - id: uv-export\n"
    )

    assert [
        f.extracted_dep for f in findings
        if f.pattern_id == "precommit-repo"
    ] == ["https://github.com/astral-sh/uv-pre-commit@0.5.26"]


def test_keeps_distinct_revisions_for_same_repo():
    findings = scan(
        "repos:\n"
        "  - repo: https://github.com/pre-commit/pre-commit-hooks\n"
        "    rev: v4.4.0\n"
        "    hooks:\n"
        "      - id: trailing-whitespace\n"
        "  - repo: https://github.com/pre-commit/pre-commit-hooks\n"
        "    rev: v5.0.0\n"
        "    hooks:\n"
        "      - id: check-yaml\n"
    )

    assert [
        f.extracted_dep for f in findings
        if f.pattern_id == "precommit-repo"
    ] == [
        "https://github.com/pre-commit/pre-commit-hooks@v4.4.0",
        "https://github.com/pre-commit/pre-commit-hooks@v5.0.0",
    ]


def test_preserves_repo_when_rev_is_missing():
    findings = scan(
        "repos:\n"
        "  - repo: https://github.com/pre-commit/pre-commit-hooks\n"
        "    hooks:\n"
        "      - id: check-yaml\n"
    )

    assert [
        f.extracted_dep for f in findings
        if f.pattern_id == "precommit-repo"
    ] == ["https://github.com/pre-commit/pre-commit-hooks"]
