"""Detect shadow dependencies in native/C++ ecosystems: Conan, vcpkg."""
from __future__ import annotations

import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class NativeDependencyScanner(BaseScanner):
    name = "native-deps"

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]):
        findings = super().scan_file_content(target, content, lines)
        if target.file_type == "conanfile" and _is_conan_test_resource_config(target.rel_path):
            return [
                finding for finding in findings
                if finding.pattern_id != "conan-requires"
            ]
        if target.file_type == "vcpkg_config" and _is_vcpkg_e2e_fixture_config(target.rel_path):
            return [
                finding for finding in findings
                if finding.pattern_id != "vcpkg-overlay-port"
            ]
        return findings

    def register_rules(self) -> None:
        # --- Conan (conanfile.txt) ---

        self.add_rule(PatternRule(
            pattern_id="conan-requires",
            regex=re.compile(
                r"^\[requires\]\s*\n(?P<dep>(?:[\w./-]+\n?)+)",
                re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="Conan package requirement: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["conanfile"],
            multiline=True,
        ))

        # Conan python_requires (code execution from remote)
        self.add_rule(PatternRule(
            pattern_id="conan-python-requires",
            regex=re.compile(
                r'python_requires\s*=\s*["\'](?P<dep>[^"\']+)["\']',
            ),
            severity=Severity.MEDIUM,
            description_template="Conan python_requires executes remote recipe code: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["conanfile"],
        ))

        # Conan custom remote URL in conanfile.py
        self.add_rule(PatternRule(
            pattern_id="conan-custom-remote",
            regex=re.compile(
                r'(?:default_remote|url)\s*=\s*["\'](?P<dep>https?://\S+?)["\']',
            ),
            severity=Severity.MEDIUM,
            description_template="Conan references custom remote server: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["conanfile"],
        ))

        # --- vcpkg (vcpkg-configuration.json) ---

        self.add_rule(PatternRule(
            pattern_id="vcpkg-git-registry",
            regex=re.compile(
                r'"kind"\s*:\s*"git"[^}]*?"repository"\s*:\s*"(?P<dep>https?://[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.HIGH,
            description_template="vcpkg custom git registry: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["vcpkg_config"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="vcpkg-custom-registry",
            regex=re.compile(
                r'"registries"\s*:\s*\[[^]]*?"repository"\s*:\s*"(?P<dep>[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="vcpkg custom registry repository: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["vcpkg_config"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="vcpkg-overlay-port",
            regex=re.compile(
                r'"(?:overlay-ports|overlay-triplets)"\s*:\s*\[\s*"(?P<dep>[^"]+)"',
            ),
            severity=Severity.MEDIUM,
            description_template="vcpkg overlay port/triplet path: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["vcpkg_config"],
        ))


def _is_vcpkg_e2e_fixture_config(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").lower().split("/")
    return "e2e-projects" in parts


def _is_conan_test_resource_config(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").lower().split("/")
    has_test_path = any(part in {"test", "tests", "testing"} or part.endswith("tests") for part in parts[:-1])
    has_fixture_data = any(
        part in {"resource", "resources", "fixture", "fixtures", "testdata", "test-data"}
        for part in parts[:-1]
    )
    return has_test_path and has_fixture_data
