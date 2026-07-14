"""Tests for AgentInstructionScanner."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.agent_instructions import AgentInstructionScanner


def scan(content: str, rel_path: str = "pkg/mcp/tools.go"):
    scanner = AgentInstructionScanner(Config())
    target = FileTarget(path=Path(rel_path), rel_path=rel_path, file_type="source_code")
    return scanner.scan_file_content(target, content, content.splitlines())


def scan_agent_instruction(content: str, rel_path: str = "skills/demo/SKILL.md"):
    scanner = AgentInstructionScanner(Config())
    target = FileTarget(path=Path(rel_path), rel_path=rel_path, file_type="agent_instruction")
    return scanner.scan_file_content(target, content, content.splitlines())


def test_detects_install_command_field_in_source():
    findings = scan('Dependencies: []Dependency{{Name: "acme-pay", InstallCommand: "npm install acme-pay"}},\n')

    assert any(
        f.pattern_id == "agent-source-npm-install" and f.extracted_dep == "acme-pay"
        for f in findings
    )


def test_ignores_agent_source_comment_install_example():
    findings = scan(
        "// The same shape npm install @openai/codex produces.\n"
        "// Users can install with `npm install -g @openai/codex`.\n",
        rel_path="src/agent/service.ts",
    )

    assert findings == []


def test_ignores_python_agent_source_comment_install_example():
    findings = scan(
        "# ``apm install --mcp foo -- npx -y srv`` is accepted syntax.\n"
        'help_text = "Run npx real-server"\n',
        rel_path="src/apm_cli/commands/mcp.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "agent-source-npx-execution"
    }
    assert deps == {"real-server"}


def test_agent_source_npm_and_npx_ignore_status_prose_tokens():
    findings = scan(
        "debugLog(`npm install failed, trying alternative installation methods`)\n"
        "console.error(`If using npx, clear the npx cache and try again:`)\n"
        "console.error(`   npx -y clear-npx-cache`)\n"
        "const command = 'npm install @azure/mcp';\n",
        rel_path="eng/npm/wrapper/index.js",
    )

    deps = {
        (f.pattern_id, f.extracted_dep)
        for f in findings
    }
    assert ("agent-source-npm-install", "@azure/mcp") in deps
    assert ("agent-source-npx-execution", "clear-npx-cache") in deps
    assert ("agent-source-npm-install", "failed") not in deps
    assert ("agent-source-npx-execution", "cache") not in deps


def test_ignores_agent_source_test_files():
    findings = scan(
        'def test_command():\n'
        '    assert command == "npx -y @modelcontextprotocol/server-fetch"\n',
        rel_path="tests/unit/test_mcp_command.py",
    )

    assert findings == []


def test_ignores_agent_source_camel_case_test_files():
    findings = scan(
        'const result = parseBashCommand("npm install --save-dev typescript");\n',
        rel_path="src/mcpValidationTest.ts",
    )

    assert findings == []


def test_ignores_generated_bundle_with_agent_like_diagnostic_text():
    findings = scan(
        'const msg = "MCP diagnostic: Try npm i --save-dev @types/node to fix this";\n',
        rel_path="samples/apps/monaco-editor/Monaco/Assets/vs/assets/ts.worker-CMbG-7ft.js",
    )

    assert findings == []


def test_detects_mcp_template_npx_instruction():
    findings = scan(
        "const msg = `Create the project using npx degit acme-co/widgets/template`;\n",
        rel_path="packages/widgets-mcp/src/tools/create.ts",
    )

    assert any(
        f.pattern_id == "agent-source-npx-execution" and f.extracted_dep == "degit"
        for f in findings
    )


def test_agent_source_pip_install_ignores_requirements_file_after_flags():
    findings = scan(
        'const dockerfile = "RUN pip install --no-cache-dir -r requirements.txt";\n'
        'const help = "Install it with: pip install agent-framework-openai";\n',
        rel_path="python/packages/openai/agent_framework_openai/_shared.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "agent-source-pip-install"
    }
    assert deps == {"agent-framework-openai"}


def test_agent_source_pip_install_ignores_negated_prose():
    findings = scan(
        'message = "The local mock needs no pip install and no virtualenv — just python3."\n'
        'hint = "Install it with: pip install useful-package"\n',
        rel_path="src/agent/build_guide_video.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "agent-source-pip-install"
    }
    assert deps == {"useful-package"}


def test_agent_source_pip_install_ignores_generic_docstring_prose_tokens():
    findings = scan(
        '"""Detect unregistered package names in pip install commands.\n'
        'Extract package names from a pip install argument string.\n'
        'Check a file for pip install targets.\n'
        '"""\n'
        'hint = "Install it with: pip install useful-package"\n',
        rel_path="src/agent/check_dependency_confusion.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "agent-source-pip-install"
    }
    assert deps == {"useful-package"}


def test_agent_source_pip_install_ignores_docstring_requirements_section():
    findings = scan(
        '"""PR Review Poster\n'
        '\n'
        'Requirements:\n'
        '    pip install PyYAML\n'
        '"""\n'
        'hint = "Install it with: pip install useful-package"\n',
        rel_path=".claude/skills/review-pr/review-pr.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "agent-source-pip-install"
    }
    assert deps == {"useful-package"}


def test_agent_source_pip_install_ignores_local_artifact_path_fragment():
    findings = scan(
        'print("2. Test locally: pip install dist/*.whl")\n'
        'hint = "Install it with: pip install useful-package"\n',
        rel_path="src/agent/prepare_pypi.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "agent-source-pip-install"
    }
    assert deps == {"useful-package"}


def test_agent_source_pip_install_reports_each_package_operand():
    findings = scan(
        'print("Error: pandas required. Install with: pip install pandas pyarrow")\n',
        rel_path="skills/microsoft-foundry/finetuning/scripts/convert_dataset.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "agent-source-pip-install"
    }
    assert deps == {"pandas", "pyarrow"}


def test_agent_source_pip_install_stops_at_closing_string_literal():
    findings = scan(
        'raise ImportError("pyyaml is required: pip install pyyaml") from exc\n',
        rel_path="agent-governance-python/agent-compliance/src/agent_compliance/lint_policy.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "agent-source-pip-install"
    }
    assert deps == {"pyyaml"}


def test_agent_source_pip_install_handles_versioned_first_package():
    findings = scan(
        'lines.append("pip install azure-ai-projects>=2.0.0 azure-ai-agents azure-identity")\n',
        rel_path="src/agent/generate_llms_full.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "agent-source-pip-install"
    }
    assert deps == {"azure-ai-projects>=2.0.0", "azure-ai-agents", "azure-identity"}


def test_agent_source_pip_install_dedupes_same_file_dependency():
    findings = scan(
        'print("ERROR: requests not found. Run: pip install requests")\n'
        'print("ERROR: urllib3 / requests not found. Run: pip install requests")\n'
        'print("ERROR: msal not found. Run: pip install msal")\n',
        rel_path="solutions/ess-maker-skills/scripts/flightcheck/graph_client.py",
    )

    deps = [
        f.extracted_dep for f in findings
        if f.pattern_id == "agent-source-pip-install"
    ]
    assert deps == ["requests", "msal"]


def test_agent_source_go_get_ignores_angle_bracket_placeholder():
    findings = scan(
        '"go": "- Run: `go get <module>` only when a non-standard module is genuinely required\\n"\n'
        '"1. Run `go get <module>`.\\n"\n',
        rel_path="CoderMind/scripts/code_gen/batch_prompts.py",
    )

    assert not any(f.pattern_id == "agent-source-go-get" for f in findings)


def test_agent_source_go_get_keeps_concrete_module():
    findings = scan(
        'hint = "Run: go get github.com/example/tool when the tool is missing"\n',
        rel_path="src/agent/install_hints.py",
    )

    assert any(
        f.pattern_id == "agent-source-go-get"
        and f.extracted_dep == "github.com/example/tool"
        for f in findings
    )


def test_agent_source_brew_install_skips_cask_flag():
    findings = scan(
        'logger.error("  macOS:   brew install --cask libreoffice")\n',
        rel_path=".github/skills/experimental/powerpoint/scripts/export_slides.py",
    )

    assert any(
        f.pattern_id == "agent-source-brew-install"
        and f.extracted_dep == "libreoffice"
        for f in findings
    )
    assert not any(
        f.pattern_id == "agent-source-brew-install"
        and f.extracted_dep == "--cask"
        for f in findings
    )


def test_detects_update_command_global_npm_instruction():
    findings = scan(
        "export const update_command = 'Run: npm install -g @stripe/link-cli';\n",
        rel_path="packages/cli/src/utils/update-info.ts",
    )

    assert any(
        f.pattern_id == "agent-source-npm-global-install"
        and f.extracted_dep == "@stripe/link-cli"
        for f in findings
    )


def test_detects_skills_add_instruction_in_go_source():
    findings = scan(
        'package main\nconst msg = "Run npx skills add --all stripe/ai"\n',
        rel_path="pkg/cmd/root.go",
    )

    assert any(
        f.pattern_id == "agent-source-npx-execution" and f.extracted_dep == "skills"
        for f in findings
    )


def test_parses_skill_frontmatter_openclaw_metadata():
    findings = scan_agent_instruction(
        """---
name: demo
allowed-tools: Bash(link-cli:*), Bash(npx:*), Bash(npm:*)
metadata:
  openclaw:
    requires:
      bins: [link-cli]
    install:
      kind: node
      package: "@stripe/link-cli"
      bins: [link-cli]
---
# Demo
"""
    )

    assert any(
        f.pattern_id == "skill-openclaw-install-package"
        and f.extracted_dep == "@stripe/link-cli"
        for f in findings
    )
    assert any(
        f.pattern_id == "skill-allowed-tool-runner" and f.extracted_dep == "npx"
        for f in findings
    )


def test_ignores_ordinary_application_source_without_agent_hints():
    findings = scan(
        'const help = "Run npm install left-pad";\n',
        rel_path="src/help.ts",
    )

    assert findings == []


def test_ignores_ordinary_global_install_string_without_agent_hints():
    findings = scan(
        'const help = "Run npm install -g left-pad";\n',
        rel_path="src/help.ts",
    )

    assert findings == []
