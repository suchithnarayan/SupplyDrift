"""Detect shadow dependencies in JVM and BEAM ecosystems: Scala/sbt, Elixir/Mix, Erlang/Rebar."""
from __future__ import annotations

import re

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class JvmBeamDependencyScanner(BaseScanner):
    name = "jvm-beam-deps"

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        findings = super().scan_file_content(target, content, lines)
        _normalize_sbt_plugin_dependencies(findings)
        return findings

    def register_rules(self) -> None:
        # --- Scala / sbt ---

        self.add_rule(PatternRule(
            pattern_id="sbt-custom-resolver",
            regex=re.compile(
                r'resolvers\s*\+=\s*"[^"]*"\s+at\s+"(?P<dep>https?://[^"]+)"',
            ),
            severity=Severity.MEDIUM,
            description_template="sbt custom resolver (non-standard Maven/Ivy repository): {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["sbt_build"],
        ))

        self.add_rule(PatternRule(
            pattern_id="sbt-resolver-url",
            regex=re.compile(
                r'resolvers\s*\+\+=\s*Seq\s*\([^)]*?"[^"]*"\s+at\s+"(?P<dep>https?://[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="sbt custom resolver in sequence: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["sbt_build"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="sbt-plugin-addSbtPlugin",
            regex=re.compile(
                r'addSbtPlugin\s*\(\s*"(?P<org>[^"]+)"\s*%\s*"(?P<name>[^"]+)"\s*%\s*"(?P<version>[^"]+)"',
            ),
            severity=Severity.LOW,
            description_template="sbt plugin dependency: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["sbt_build"],
            extract_group="org",
        ))

        # --- Elixir / Mix ---

        self.add_rule(PatternRule(
            pattern_id="mix-git-dependency",
            regex=re.compile(
                r'\{:\w+,\s*git:\s*"(?P<dep>[^"]+)"',
            ),
            severity=Severity.MEDIUM,
            description_template="Elixir/Mix dependency from git source: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["mix_config"],
        ))

        self.add_rule(PatternRule(
            pattern_id="mix-path-dependency",
            regex=re.compile(
                r'\{:\w+,\s*path:\s*"(?P<dep>[^"]+)"',
            ),
            severity=Severity.LOW,
            description_template="Elixir/Mix local path dependency: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["mix_config"],
        ))

        self.add_rule(PatternRule(
            pattern_id="mix-hex-org-override",
            regex=re.compile(
                r'\{:\w+,\s*[^}]*organization:\s*"(?P<dep>[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Elixir/Mix dependency from private Hex organization: {dep}",
            category=Category.REGISTRY_CONFIG,
            file_types=["mix_config"],
            multiline=True,
        ))

        # --- Erlang / Rebar ---

        self.add_rule(PatternRule(
            pattern_id="rebar-git-dependency",
            regex=re.compile(
                r'\{git,\s*"(?P<dep>[^"]+)"',
            ),
            severity=Severity.MEDIUM,
            description_template="Erlang/Rebar dependency from git source: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["rebar_config"],
        ))


_SBT_PLUGIN_RE = re.compile(
    r'addSbtPlugin\s*\(\s*"(?P<org>[^"]+)"\s*%\s*"(?P<name>[^"]+)"\s*%\s*"(?P<version>[^"]+)"',
)


def _normalize_sbt_plugin_dependencies(findings: list[Finding]) -> None:
    for finding in findings:
        if finding.pattern_id != "sbt-plugin-addSbtPlugin":
            continue
        match = _SBT_PLUGIN_RE.search(finding.matched_text)
        if not match:
            continue
        dep = f"{match.group('org')}:{match.group('name')}:{match.group('version')}"
        finding.extracted_dep = dep
        finding.description = f"sbt plugin dependency: {dep}"
