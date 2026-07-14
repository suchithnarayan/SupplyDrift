"""Bazel external dependency rules (http_archive, git_repository, http_file)."""
from __future__ import annotations

import re

from github_inventory.models import Category, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class BazelDependencyScanner(BaseScanner):
    name = "bazel-dependencies"

    def register_rules(self) -> None:
        # http_archive with url/urls containing a URL
        self.add_rule(PatternRule(
            pattern_id="bazel-http-archive",
            regex=re.compile(
                r'http_archive\s*\([^)]*?(?:url|urls)\s*=\s*["\[]\s*"(?P<dep>https?://[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Bazel http_archive pulls external dependency: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
            multiline=True,
        ))

        # http_file with url
        self.add_rule(PatternRule(
            pattern_id="bazel-http-file",
            regex=re.compile(
                r'http_file\s*\([^)]*?(?:url|urls)\s*=\s*["\[]\s*"(?P<dep>https?://[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Bazel http_file pulls external file: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["build"],
            multiline=True,
        ))

        # git_repository with remote
        self.add_rule(PatternRule(
            pattern_id="bazel-git-repository",
            regex=re.compile(
                r'git_repository\s*\([^)]*?remote\s*=\s*"(?P<dep>[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Bazel git_repository pulls external repo: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["build"],
            multiline=True,
        ))

        # Nix fetchurl/fetchFromGitHub/fetchgit
        self.add_rule(PatternRule(
            pattern_id="nix-fetch-url",
            regex=re.compile(
                r'fetchurl\s*\{[^}]*?url\s*=\s*"(?P<dep>https?://[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Nix fetchurl pulls external resource: {dep}",
            category=Category.BUILD_EXTERNAL,
            file_types=["nix"],
            multiline=True,
        ))

        self.add_rule(PatternRule(
            pattern_id="nix-fetch-from-github",
            regex=re.compile(
                r'fetchFromGitHub\s*\{[^}]*?owner\s*=\s*"(?P<dep>[^"]+)"[^}]*?repo\s*=\s*"(?P<repo>[^"]+)"',
                re.DOTALL,
            ),
            severity=Severity.MEDIUM,
            description_template="Nix fetchFromGitHub pulls external repo: {dep}",
            category=Category.GIT_DEPENDENCY,
            file_types=["nix"],
            multiline=True,
        ))
