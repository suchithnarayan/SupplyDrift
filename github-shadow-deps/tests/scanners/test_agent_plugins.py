"""Tests for AgentPluginScanner."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Severity
from github_inventory.scanners.agent_plugins import AgentPluginScanner


def scan(content: str):
    scanner = AgentPluginScanner(Config())
    path = Path("marketplace.json")
    target = FileTarget(path=path, rel_path=".codex-plugin/marketplace.json", file_type="agent_plugin")
    return scanner.scan_file_content(target, content, content.splitlines())


def test_flags_remote_plugin_source_with_sha():
    findings = scan(
        """
        {
          "plugins": [{
            "name": "example",
            "source": {
              "source": "url",
              "url": "https://github.com/example/plugin.git",
              "sha": "0123456789012345678901234567890123456789"
            }
          }]
        }
        """
    )

    match = next(f for f in findings if f.extracted_dep == "https://github.com/example/plugin.git")
    assert match.pattern_id == "agent-plugin-source-url"
    assert match.severity == Severity.HIGH


def test_escalates_remote_plugin_source_without_sha():
    findings = scan(
        """
        {
          "plugins": [{
            "name": "example",
            "source": {
              "source": "git-subdir",
              "url": "https://github.com/example/plugin.git",
              "path": "plugins/example",
              "ref": "main"
            }
          }]
        }
        """
    )

    match = next(f for f in findings if f.extracted_dep == "https://github.com/example/plugin.git")
    assert match.pattern_id == "agent-plugin-source-url-unpinned"
    assert match.severity == Severity.CRITICAL


def test_ignores_local_plugin_source():
    findings = scan('{"plugins": [{"name": "local", "source": "./plugins/local"}]}')

    assert findings == []
