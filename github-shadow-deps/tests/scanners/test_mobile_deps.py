"""Tests for MobileDependencyScanner."""
from __future__ import annotations

import tempfile
from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.mobile_deps import MobileDependencyScanner


def scan(content: str, rel_path: str, file_type: str = "package_config"):
    scanner = MobileDependencyScanner(Config())
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(content)
        p = Path(f.name)
    target = FileTarget(path=p, rel_path=rel_path, file_type=file_type)
    return scanner.scan_file(target)


def test_podfile_custom_source_is_reported_for_podfile():
    findings = scan('source "https://cdn.cocoapods.org/"\n', "ios/Podfile")

    assert any(
        f.pattern_id == "podfile-custom-source"
        and f.extracted_dep == "https://cdn.cocoapods.org/"
        for f in findings
    )


def test_ruby_gemfile_source_is_not_reported_as_podfile_source():
    findings = scan('source "https://rubygems.org"\n', "Gemfile")

    assert not any(f.pattern_id == "podfile-custom-source" for f in findings)
