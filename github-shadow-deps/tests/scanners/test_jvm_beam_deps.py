"""Tests for JvmBeamDependencyScanner."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.jvm_beam_deps import JvmBeamDependencyScanner


def scan(content: str, file_type: str = "sbt_build", rel_path: str = "project/plugins.sbt"):
    scanner = JvmBeamDependencyScanner(Config())
    target = FileTarget(path=Path(rel_path), rel_path=rel_path, file_type=file_type)
    return scanner.scan_file_content(target, content, content.splitlines())


def test_sbt_plugin_extracts_full_coordinate():
    findings = scan('addSbtPlugin("com.eed3si9n" % "sbt-unidoc" % "0.4.2")\n')

    assert any(
        f.pattern_id == "sbt-plugin-addSbtPlugin"
        and f.extracted_dep == "com.eed3si9n:sbt-unidoc:0.4.2"
        and f.description == "sbt plugin dependency: com.eed3si9n:sbt-unidoc:0.4.2"
        for f in findings
    )


def test_sbt_custom_resolver_still_reports_url():
    findings = scan('resolvers += "internal" at "https://repo.example.com/maven2"\n')

    assert any(
        f.pattern_id == "sbt-custom-resolver"
        and f.extracted_dep == "https://repo.example.com/maven2"
        for f in findings
    )
