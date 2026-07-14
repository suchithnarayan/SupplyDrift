"""Tests for MCPServerScanner."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Severity
from github_inventory.scanners.mcp_servers import MCPServerScanner


def scan(content: str, rel_path: str = "mcp.json"):
    scanner = MCPServerScanner(Config())
    path = Path(rel_path)
    target = FileTarget(path=path, rel_path=rel_path, file_type="mcp_config")
    return scanner.scan_file_content(target, content, content.splitlines())


def test_flags_npx_package_without_yes_arg():
    findings = scan('{"playwright": {"command": "npx", "args": ["@playwright/mcp@latest"]}}')

    match = next(f for f in findings if f.extracted_dep == "@playwright/mcp@latest")
    assert match.pattern_id == "mcp-server-runner-package"
    assert match.severity == Severity.CRITICAL


def test_flags_pnpx_package():
    findings = scan('{"stripe": {"command": "pnpx", "args": ["@stripe/link-cli", "--mcp"]}}')

    assert any(
        f.pattern_id == "mcp-server-runner-package"
        and f.extracted_dep == "@stripe/link-cli"
        for f in findings
    )


def test_flags_pnpm_dlx_package():
    findings = scan('{"stripe": {"command": "pnpm", "args": ["dlx", "@stripe/link-cli", "--mcp"]}}')

    assert any(
        f.pattern_id == "mcp-server-runner-package"
        and f.extracted_dep == "@stripe/link-cli"
        for f in findings
    )


def test_flags_uvx_from_git_source():
    findings = scan(
        '{"serena": {"command": "uvx", "args": ["--from", '
        '"git+https://github.com/oraios/serena", "serena", "start-mcp-server"]}}'
    )

    assert any(
        f.pattern_id == "mcp-server-runner-package"
        and f.extracted_dep == "git+https://github.com/oraios/serena"
        for f in findings
    )


def test_flags_dnx_package_runner():
    findings = scan('{"hex1b": {"command": "dnx", "args": ["Hex1b.McpServer@0.133.0", "--yes"]}}')

    assert any(
        f.pattern_id == "mcp-server-runner-package"
        and f.extracted_dep == "Hex1b.McpServer@0.133.0"
        for f in findings
    )
    assert not any(
        f.pattern_id == "mcp-server-arbitrary-command"
        and f.extracted_dep == "dnx"
        for f in findings
    )


def test_ignores_npm_run_local_script_server():
    findings = scan(
        '{"servers": {"local": {'
        '"command": "npm", '
        '"args": ["run", "start-stdio"], '
        '"cwd": "${workspaceFolder}/test/mcp"'
        '}}}',
        rel_path=".vscode/mcp.json",
    )

    assert findings == []


def test_ignores_npm_exec_no_install_local_binary():
    findings = scan(
        '{"servers": {"component-explorer": {'
        '"command": "npm", '
        '"args": ["exec", "--no", "--", "component-explorer", "mcp"]'
        '}}}',
        rel_path=".vscode/mcp.json",
    )

    assert findings == []


def test_flags_npm_exec_package_resolution():
    findings = scan(
        '{"servers": {"remote-tool": {'
        '"command": "npm", '
        '"args": ["exec", "--yes", "@modelcontextprotocol/server-filesystem"]'
        '}}}',
        rel_path=".vscode/mcp.json",
    )

    assert any(
        f.pattern_id == "mcp-server-runner-package"
        and f.extracted_dep == "@modelcontextprotocol/server-filesystem"
        for f in findings
    )
    assert not any(f.pattern_id == "mcp-server-arbitrary-command" for f in findings)


def test_jsonc_trailing_comma_stays_on_structured_path():
    findings = scan(
        '{\n'
        '  "servers": {\n'
        '    "local": {\n'
        '      "command": "npm",\n'
        '      "args": ["run", "start-stdio", "--"],\n'
        '    },\n'
        '  },\n'
        '}\n',
        rel_path=".vscode/mcp.json",
    )

    assert findings == []


def test_flags_remote_endpoint():
    findings = scan('{"asana": {"url": "https://mcp.asana.com/sse"}}')

    assert any(f.pattern_id == "mcp-server-remote-url" for f in findings)


def test_ignores_placeholder_mcp_values_in_fixture_config():
    findings = scan(
        '{"mcpServers": {'
        '"remote": {"url": "https://example.invalid/mcp"}, '
        '"stdio": {"command": "npx", "args": ["-y", "some-pkg"]}'
        '}}',
        rel_path="tests/integration/fixtures/claude_mcp_golden/project_mcp.json",
    )

    assert not any(f.pattern_id == "mcp-server-remote-url" for f in findings)
    assert not any(f.pattern_id == "mcp-server-runner-package" for f in findings)


def test_fixture_mcp_config_still_reports_real_remote_and_runner_package():
    findings = scan(
        '{"mcpServers": {'
        '"remote": {"url": "https://mcp.example.com/sse"}, '
        '"stdio": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]}'
        '}}',
        rel_path="tests/integration/fixtures/claude_mcp_golden/project_mcp.json",
    )

    assert any(
        f.pattern_id == "mcp-server-remote-url"
        and f.extracted_dep == "https://mcp.example.com/sse"
        for f in findings
    )
    assert any(
        f.pattern_id == "mcp-server-runner-package"
        and f.extracted_dep == "@modelcontextprotocol/server-filesystem"
        for f in findings
    )


def test_ignores_jsonc_commented_remote_endpoint():
    findings = scan(
        '{\n'
        '  "servers": {\n'
        '    "local": {"command": "dotnet"}\n'
        '    // "remote": {"url": "http://localhost:3001"}\n'
        '  }\n'
        '}\n',
        rel_path=".vscode/mcp.json",
    )

    assert any(
        f.pattern_id == "mcp-server-arbitrary-command"
        and f.extracted_dep == "dotnet"
        for f in findings
    )
    assert not any(f.pattern_id == "mcp-server-remote-url" for f in findings)


def test_regex_fallback_ignores_jsonc_commented_remote_endpoint():
    findings = scan(
        '{\n'
        '  // "url": "https://mcp.example.test/sse"\n'
        '  "command": "customctl",\n',
        rel_path=".vscode/mcp.json",
    )

    assert any(
        f.pattern_id == "mcp-server-arbitrary-command"
        and f.extracted_dep == "customctl"
        for f in findings
    )
    assert not any(f.pattern_id == "mcp-server-remote-url" for f in findings)


def test_flags_docker_run_image():
    findings = scan('{"terraform": {"command": "docker", "args": ["run", "hashicorp/terraform-mcp-server"]}}')

    assert any(
        f.pattern_id == "mcp-server-docker-image"
        and f.extracted_dep == "hashicorp/terraform-mcp-server"
        and f.severity == Severity.CRITICAL
        for f in findings
    )
    assert not any(
        f.pattern_id == "mcp-server-arbitrary-command"
        and f.extracted_dep == "docker"
        for f in findings
    )


def test_flags_docker_run_image_after_options():
    findings = scan(
        '{"crisp": {"command": "docker", "args": ['
        '"run", "--rm", "-i", "--name", "crisp-mcp-server", "anmalkov/mcp-crisp:latest"'
        ']}}'
    )

    assert any(
        f.pattern_id == "mcp-server-docker-image"
        and f.extracted_dep == "anmalkov/mcp-crisp:latest"
        and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_flags_custom_docker_command_without_run_image():
    findings = scan('{"docker": {"command": "docker", "args": ["version"]}}')

    assert any(
        f.pattern_id == "mcp-server-arbitrary-command"
        and f.extracted_dep == "docker"
        for f in findings
    )


def test_flags_custom_command():
    findings = scan('{"custom": {"command": "customctl", "args": ["serve"]}}')

    assert any(f.pattern_id == "mcp-server-arbitrary-command" for f in findings)


def test_flags_content_discovered_mcp_servers_object():
    findings = scan(
        '{"mcpServers": {"custom": {"command": "customctl", "args": ["serve"]}}}',
        rel_path="gemini-extension.json",
    )

    assert any(
        f.pattern_id == "mcp-server-arbitrary-command"
        and f.extracted_dep == "customctl"
        for f in findings
    )


def test_flags_list_valued_mcp_servers_entries():
    findings = scan(
        '{'
        '  "mcpServers": ['
        '    {"mcpServerName": "mail", "url": "https://agent365.example/mcp_MailTools"},'
        '    {"mcpServerName": "playwright", "command": "npx", "args": ["@playwright/mcp@latest"]}'
        '  ]'
        '}',
        rel_path="ToolingManifest.json",
    )

    assert any(
        f.pattern_id == "mcp-server-remote-url"
        and f.extracted_dep == "https://agent365.example/mcp_MailTools"
        for f in findings
    )
    assert any(
        f.pattern_id == "mcp-server-runner-package"
        and f.extracted_dep == "@playwright/mcp@latest"
        and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_ignores_localization_json_with_mcp_words():
    findings = scan(
        '{"contents": {"settings": {"mcpServers": "MCP servers", "command": "Command:"}}}',
        rel_path="translations/main.i18n.json",
    )

    assert findings == []
