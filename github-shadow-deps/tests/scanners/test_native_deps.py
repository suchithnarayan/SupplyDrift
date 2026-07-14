"""Tests for NativeDependencyScanner."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.native_deps import NativeDependencyScanner


def scan(content: str, name: str = "vcpkg-configuration.json", file_type: str = "vcpkg_config"):
    scanner = NativeDependencyScanner(Config())
    target = FileTarget(path=Path(name), rel_path=name, file_type=file_type)
    return scanner.scan_file_content(target, content, content.splitlines())


def test_vcpkg_overlay_port_is_reported_for_project_config():
    findings = scan('{"overlay-ports": ["./ports"]}\n')

    assert any(
        f.pattern_id == "vcpkg-overlay-port" and f.extracted_dep == "./ports"
        for f in findings
    )


def test_vcpkg_overlay_port_is_ignored_for_e2e_fixture_config():
    findings = scan(
        '{"overlay-ports": ["./config-overlays"]}\n',
        name="azure-pipelines/e2e-projects/overlays-dot/vcpkg-configuration.json",
    )

    assert not any(f.pattern_id == "vcpkg-overlay-port" for f in findings)


def test_vcpkg_e2e_fixture_still_reports_git_registry():
    findings = scan(
        """{
  "registries": [{
    "kind": "git",
    "repository": "https://github.com/example/vcpkg-registry",
    "baseline": "0123456789abcdef0123456789abcdef01234567"
  }],
  "overlay-ports": ["./config-overlays"]
}
""",
        name="azure-pipelines/e2e-projects/overlays-dot/vcpkg-configuration.json",
    )

    assert any(
        f.pattern_id == "vcpkg-git-registry"
        and f.extracted_dep == "https://github.com/example/vcpkg-registry"
        for f in findings
    )
    assert not any(f.pattern_id == "vcpkg-overlay-port" for f in findings)


def test_conan_requires_is_reported_for_project_config():
    findings = scan(
        "[requires]\nboost/1.82.0\n",
        name="conanfile.txt",
        file_type="conanfile",
    )

    assert any(
        f.pattern_id == "conan-requires" and f.extracted_dep == "boost/1.82.0"
        for f in findings
    )


def test_conan_requires_is_ignored_for_test_resource_config():
    findings = scan(
        "[requires]\nboost/1.82.0\n",
        name="test/Microsoft.ComponentDetection.VerificationTests/resources/conan/conanTextFile/conanfile.txt",
        file_type="conanfile",
    )

    assert not any(f.pattern_id == "conan-requires" for f in findings)
