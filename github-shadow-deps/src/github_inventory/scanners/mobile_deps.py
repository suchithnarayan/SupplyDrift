"""Detect shadow dependencies in mobile ecosystems: Dart/Flutter, CocoaPods, Carthage."""
from __future__ import annotations

import re

from github_inventory.models import Category, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class MobileDependencyScanner(BaseScanner):
    name = "mobile-deps"

    def scan_file_content(self, target, content: str, lines: list[str]):
        findings = super().scan_file_content(target, content, lines)
        if _is_podfile_path(target.rel_path):
            return findings
        return [
            finding for finding in findings
            if not finding.pattern_id.startswith("podfile-")
        ]

    def register_rules(self) -> None:
        # --- Dart / Flutter (pubspec.yaml) ---

        self.add_rule(PatternRule(
            pattern_id="pubspec-git-dependency",
            regex=re.compile(
                r"git:\s*\n\s+url:\s*(?P<dep>\S+)",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Dart/Flutter dependency from git source: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["pubspec"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="pubspec-hosted-url-override",
            regex=re.compile(
                r"hosted:\s*\n\s+(?:name:\s*\S+\s*\n\s+)?url:\s*(?P<dep>(?!https?://pub\.dev)\S+)",
                re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="Dart/Flutter uses non-default package server (dependency confusion risk): {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["pubspec"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="pubspec-path-dependency",
            regex=re.compile(
                r"path:\s*(?P<dep>(?:\.\./|\./|/)\S+)",
            ),
            severity=Severity.LOW,
            description_template="Dart/Flutter local path dependency (may mask published version): {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["pubspec"],
        ))

        # --- CocoaPods (Podfile + podspec) ---

        self.add_rule(PatternRule(
            pattern_id="podfile-custom-source",
            regex=re.compile(
                r"^source\s+['\"](?P<dep>https?://\S+)['\"]",
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="CocoaPods uses custom spec source: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["package_config"],
        ))

        self.add_rule(PatternRule(
            pattern_id="podfile-git-pod",
            regex=re.compile(
                r"pod\s+['\"][\w/.-]+['\"][^,\n]*,\s*:git\s*=>\s*['\"](?P<dep>[^'\"]+)['\"]",
            ),
            severity=Severity.MEDIUM,
            description_template="CocoaPods pod from git source: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["package_config"],
        ))

        self.add_rule(PatternRule(
            pattern_id="podspec-source-git",
            regex=re.compile(
                r"\.source\s*=\s*\{[^}]*:git\s*=>\s*['\"](?P<dep>[^'\"]+)['\"]",
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Podspec source from git repository: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["podspec"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="podspec-source-http",
            regex=re.compile(
                r"\.source\s*=\s*\{[^}]*:http\s*=>\s*['\"](?P<dep>https?://[^'\"]+)['\"]",
                re.DOTALL,
            ),
            severity=Severity.HIGH,
            description_template="Podspec source downloads from HTTP URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=["podspec"],
            multiline=True,
        ))

        # --- Carthage (Cartfile) ---

        self.add_rule(PatternRule(
            pattern_id="carthage-github-dep",
            regex=re.compile(
                r'^github\s+"(?P<dep>[^"]+)"',
                re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="Carthage GitHub dependency: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["cartfile"],
        ))

        self.add_rule(PatternRule(
            pattern_id="carthage-git-dep",
            regex=re.compile(
                r'^git\s+"(?P<dep>[^"]+)"',
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Carthage git dependency: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["cartfile"],
        ))

        self.add_rule(PatternRule(
            pattern_id="carthage-binary-dep",
            regex=re.compile(
                r'^binary\s+"(?P<dep>https?://[^"]+)"',
                re.MULTILINE,
            ),
            severity=Severity.HIGH,
            description_template="Carthage binary framework from remote URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=["cartfile"],
        ))


def _is_podfile_path(rel_path: str) -> bool:
    return rel_path.replace("\\", "/").rsplit("/", 1)[-1] == "Podfile"
