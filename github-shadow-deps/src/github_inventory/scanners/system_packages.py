"""
System package list files: Brewfile, Aptfile, apt-packages.

These declare system-level packages installed by `brew bundle`,
Heroku/Render apt buildpacks, or similar tooling. Each line is a
shadow dependency relative to the project's language manifest, since
they live outside requirements.txt / package.json / Cargo.toml.
"""
from __future__ import annotations

import re

from github_inventory.models import Category, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class SystemPackageListScanner(BaseScanner):
    name = "system-packages-list"

    def register_rules(self) -> None:
        # Brewfile: `brew "pkg"` or `brew "pkg", args: [...]`. Tap directives
        # (`tap "..."`) bring in a non-default Homebrew tap, which is higher
        # risk than the formula itself.
        self.add_rule(PatternRule(
            pattern_id="brewfile-tap",
            regex=re.compile(
                r'^\s*tap\s+["\'](?P<dep>[\w./-]+)["\']',
                re.MULTILINE,
            ),
            severity=Severity.MEDIUM,
            description_template="Brewfile registers non-default Homebrew tap: {dep}",
            category=Category.SYSTEM_PACKAGE_LIST,
            file_types=["system_packages"],
        ))
        self.add_rule(PatternRule(
            pattern_id="brewfile-formula",
            regex=re.compile(
                r'^\s*brew\s+["\'](?P<dep>[\w@/.-]+)["\']',
                re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="Brewfile installs Homebrew formula: {dep}",
            category=Category.SYSTEM_PACKAGE_LIST,
            file_types=["system_packages"],
        ))
        self.add_rule(PatternRule(
            pattern_id="brewfile-cask",
            regex=re.compile(
                r'^\s*cask\s+["\'](?P<dep>[\w@/.-]+)["\']',
                re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="Brewfile installs Homebrew cask (GUI app): {dep}",
            category=Category.SYSTEM_PACKAGE_LIST,
            file_types=["system_packages"],
        ))

        # Aptfile / apt-packages: bare package names, one per line.
        # Skip blank/comment lines, capture the package token.
        self.add_rule(PatternRule(
            pattern_id="aptfile-package",
            regex=re.compile(
                r"^(?P<dep>[a-z][\w.+-]+)\s*$",
                re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="Aptfile installs APT package via buildpack: {dep}",
            category=Category.SYSTEM_PACKAGE_LIST,
            file_types=["system_packages"],
        ))
