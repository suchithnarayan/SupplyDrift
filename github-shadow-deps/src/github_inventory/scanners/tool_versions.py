"""Tool version manager references (.tool-versions, mise.toml)."""
from __future__ import annotations

import re

from github_inventory.models import Category, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class ToolVersionScanner(BaseScanner):
    name = "tool-versions"

    def register_rules(self) -> None:
        # .tool-versions: <tool> <version> (each line is a binary download at runtime)
        self.add_rule(PatternRule(
            pattern_id="asdf-tool-version",
            regex=re.compile(
                r"^(?P<dep>[\w.-]+)\s+[\d][\w.-]*\s*$",
                re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="asdf/mise tool version manager will download: {dep}",
            category=Category.TOOL_VERSION_MANAGER,
            file_types=["toolversions"],
        ))

        # mise.toml: [tools] section entries like node = "20"
        self.add_rule(PatternRule(
            pattern_id="mise-tool-entry",
            regex=re.compile(
                r'^(?P<dep>[\w.-]+)\s*=\s*["\'][\d][\w.-]*["\']',
                re.MULTILINE,
            ),
            severity=Severity.LOW,
            description_template="mise tool entry will download binary: {dep}",
            category=Category.TOOL_VERSION_MANAGER,
            file_types=["toolversions"],
        ))
