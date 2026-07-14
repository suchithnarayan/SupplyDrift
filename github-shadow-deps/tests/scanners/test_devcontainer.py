"""Tests for DevcontainerScanner."""
from __future__ import annotations

import tempfile
from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.devcontainer import DevcontainerScanner


def scan(content: str, rel_path: str = ".devcontainer/devcontainer.json"):
    scanner = DevcontainerScanner(Config())
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "devcontainer.json"
        p.write_text(content)
        target = FileTarget(path=p, rel_path=rel_path, file_type="devcontainer")
        return scanner.scan_file(target)


def test_devcontainer_features_ignore_jsonc_comments():
    findings = scan(
        '{\n'
        '  "features": {\n'
        '    "ghcr.io/devcontainers/features/docker-outside-of-docker:1": {},\n'
        '    // "ghcr.io/devcontainers/features/azure-cli:1": {},\n'
        '    /* "ghcr.io/devcontainers/features/github-cli:1": {}, */\n'
        '    "ghcr.io/devcontainers/features/git-lfs:1": {}\n'
        '  }\n'
        '}\n',
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "devcontainer-feature"
    }
    assert deps == {
        "ghcr.io/devcontainers/features/docker-outside-of-docker:1",
        "ghcr.io/devcontainers/features/git-lfs:1",
    }


def test_devcontainer_feature_drops_empty_trailing_tag_colon():
    findings = scan(
        '{\n'
        '  "features": {\n'
        '    "ghcr.io/devcontainers/features/desktop-lite:": {},\n'
        '    "ghcr.io/devcontainers/features/rust:": {}\n'
        '  }\n'
        '}\n',
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "devcontainer-feature"
    }
    assert deps == {
        "ghcr.io/devcontainers/features/desktop-lite",
        "ghcr.io/devcontainers/features/rust",
    }


def test_devcontainer_feature_keeps_version_tag_colon():
    findings = scan(
        '{\n'
        '  "features": {\n'
        '    "ghcr.io/devcontainers/features/node:1": {}\n'
        '  }\n'
        '}\n',
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "devcontainer-feature"
    }
    assert deps == {"ghcr.io/devcontainers/features/node:1"}


def test_devcontainer_image_ignored_for_test_fixture_path():
    findings = scan(
        '{\n'
        '  "image": "mcr.microsoft.com/devcontainers/python:1.1.9-3.11-bookworm"\n'
        '}\n',
        rel_path="extensions/copilot/test/simulation/fixtures/readme/.devcontainer/devcontainer.json",
    )

    assert findings == []


def test_devcontainer_image_reported_for_docs_sample_path():
    findings = scan(
        '{\n'
        '  "image": "mcr.microsoft.com/devcontainers/python:3.12-bookworm"\n'
        '}\n',
        rel_path="docs/samples/python/.devcontainer/devcontainer.json",
    )

    assert any(
        f.pattern_id == "devcontainer-image"
        and f.extracted_dep == "mcr.microsoft.com/devcontainers/python:3.12-bookworm"
        for f in findings
    )
