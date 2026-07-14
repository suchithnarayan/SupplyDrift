"""Tests for UnmanagedPackageScanner."""
from __future__ import annotations

import tempfile
from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Severity
from github_inventory.scanners.unmanaged_packages import UnmanagedPackageScanner


def scan(content: str, file_type: str = "script", name: str = "test.sh"):
    scanner = UnmanagedPackageScanner(Config())
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        target = FileTarget(path=p, rel_path=name, file_type=file_type)
        return scanner.scan_file(target)


def test_ignores_echoed_install_hint():
    findings = scan('echo "    uv pip install torch torchvision torchaudio"\n')

    assert findings == []


def test_keeps_real_uv_pip_install():
    findings = scan("uv pip install torch torchvision torchaudio\n")

    deps = {
        f.extracted_dep for f in findings
        if f.pattern_id == "uv-pip-install"
    }
    assert deps == {"torch", "torchvision", "torchaudio"}
    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_uv_python_install_detects_versions_and_project_default():
    findings = scan(
        "uv python install 3.10 3.11\n"
        "uv python install\n",
        "ci",
        ".github/workflows/ci.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "uv-python-install"
    }
    assert deps == {"3.10", "3.11", "python"}


def test_uv_python_install_detects_github_action_run_scalar():
    findings = scan(
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - run: uv python install ${{ matrix.python-version }}\n",
        "github_action",
        ".github/actions/setup-python/action.yml",
    )

    assert any(
        f.pattern_id == "uv-python-install"
        and f.extracted_dep == "${{ matrix.python-version }}"
        for f in findings
    )


def test_uv_python_install_ignores_printed_hint():
    findings = scan('echo "uv python install 3.12"\n')

    assert not any(f.pattern_id == "uv-python-install" for f in findings)


def test_ignores_unmanaged_install_in_non_control_markdown_fence():
    findings = scan(
        "Install from PyPI:\n\n"
        "```bash\n"
        "pip install sample-agent-cli\n"
        "```\n",
        "agent_instruction",
        "readme.md",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_ignores_unmanaged_install_in_non_control_reference_markdown_fence():
    findings = scan(
        "# Steps 3-5 - Download Results\n\n"
        "### Prerequisites\n\n"
        "```text\n"
        "pip install azure-ai-projects>=2.0.0 azure-identity\n"
        "```\n",
        "agent_instruction",
        "plugin/skills/microsoft-foundry/foundry-agent/observe/references/analyze-results.md",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_ignores_bare_unmanaged_install_in_non_control_reference_markdown():
    findings = scan(
        "# API Management - Python SDK Quick Reference\n\n"
        "## Install\n"
        "pip install azure-mgmt-apimanagement azure-identity\n\n"
        "## Quick Start\n"
        "```python\n"
        "from azure.identity import DefaultAzureCredential\n"
        "```\n",
        "agent_instruction",
        "plugin/skills/azure-aigateway/references/sdk/azure-mgmt-apimanagement-py.md",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_keeps_bare_unmanaged_install_in_skill_markdown():
    findings = scan(
        "---\n"
        "name: sdk-helper\n"
        "---\n\n"
        "## Setup\n"
        "pip install azure-identity requests\n",
        "agent_instruction",
        "plugin/skills/sdk-helper/SKILL.md",
    )

    assert any(
        f.pattern_id == "pip-install-ci"
        and f.extracted_dep == "azure-identity"
        for f in findings
    )


def test_ignores_unmanaged_install_in_non_control_markdown_inline_code():
    findings = scan(
        "For local testing, run `npx sample-agent-cli init`.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_uv_pip_install_reports_each_named_package_after_options():
    findings = scan(
        'uv pip install --python .venv/bin/python "bc-eval[capi]==0.3.7" '
        "anthropic pillow --quiet\n",
        "agent_instruction",
        "SKILL.md",
    )

    deps = {
        f.extracted_dep for f in findings
        if f.pattern_id == "uv-pip-install"
    }
    assert deps == {"bc-eval[capi]==0.3.7", "anthropic", "pillow"}


def test_uv_pip_install_skips_prerelease_policy_value():
    findings = scan(
        "uv pip install --prerelease allow pydantic --quiet\n",
        "script",
    )

    deps = {
        f.extracted_dep for f in findings
        if f.pattern_id == "uv-pip-install"
    }
    assert deps == {"pydantic"}
    assert "allow" not in deps


def test_uv_pip_install_skips_index_strategy_and_torch_backend_values():
    findings = scan(
        "uv pip install --index-strategy first-index --extra-index-url https://download.pytorch.org/whl/cu124 torch\n"
        "uv pip install --torch-backend cpu --no-cache-dir --no-deps --requirement -\n",
        "script",
    )

    deps = {
        f.extracted_dep for f in findings
        if f.pattern_id == "uv-pip-install"
    }
    assert deps == {"torch"}


def test_uv_pip_install_ignores_shell_comment_lines():
    findings = scan(
        "# uv pip install pyarrow azure-storage-blob\n"
        "uv pip install pydantic\n",
        "script",
    )

    deps = {
        f.extracted_dep for f in findings
        if f.pattern_id == "uv-pip-install"
    }
    assert deps == {"pydantic"}


def test_uv_tool_install_ignores_prose_connector():
    findings = scan(
        "uv tool install or npm publish -- pick one packaging path.\n",
        "agent_instruction",
        "SKILL.md",
    )

    assert not any(f.pattern_id == "uv-tool-install" for f in findings)


def test_uv_tool_install_ignores_ellipsis_placeholder():
    findings = scan(
        "Use `uv tool install git+...` for a Python CLI placeholder.\n",
        "agent_instruction",
        "SKILL.md",
    )

    assert not any(f.pattern_id == "uv-tool-install" for f in findings)


def test_uv_add_ignores_placeholder_package_tokens():
    findings = scan(
        "- Fix: `uv add package@version`\n"
        "- Fix: `uv add package-name@1.2.5`\n"
        "uv add pytest\n",
        "agent_instruction",
        "AGENTS.md",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "uv-add-in-ci"
    }
    assert deps == {"pytest"}


def test_uvx_ignores_shell_stderr_redirection_check():
    findings = scan(
        'sudo ln -sf "$HOME/.local/bin/uvx" /usr/local/bin/uvx 2>/dev/null || true\n'
        "uvx ruff --version\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "uvx-execution"
    }
    assert deps == {"ruff"}


def test_uvx_execution_detects_from_git_source_in_control_instruction():
    findings = scan(
        'uvx --from "git+https://github.com/microsoft/benchmark-qed" benchmark-qed <command>\n',
        "agent_instruction",
        "SKILL.md",
    )

    assert any(
        f.pattern_id == "uvx-execution"
        and f.extracted_dep == "git+https://github.com/microsoft/benchmark-qed"
        for f in findings
    )


def test_uvx_execution_detects_from_package_source():
    findings = scan("uvx --from shellcheck-py shellcheck -S warning -s bash\n", "script")

    assert any(
        f.pattern_id == "uvx-execution"
        and f.extracted_dep == "shellcheck-py"
        for f in findings
    )


def test_uvx_execution_skips_options_before_command():
    findings = scan(
        "git ls-files python/ | xargs uvx --with ./python --with pytest mypy\n",
        "script",
    )

    assert any(
        f.pattern_id == "uvx-execution"
        and f.extracted_dep == "mypy"
        for f in findings
    )


def test_uvx_execution_detects_command_substitution_in_echo():
    findings = scan(
        "echo \"shellcheck: $(uvx --from shellcheck-py shellcheck --version | awk '/version:/ {print $2}')\"\n",
        "script",
    )

    assert any(
        f.pattern_id == "uvx-execution"
        and f.extracted_dep == "shellcheck-py"
        for f in findings
    )


def test_uvx_execution_detects_echo_piped_input():
    findings = scan(
        'echo y | uvx --from "git+https://github.com/microsoft/benchmark-qed" benchmark-qed data download\n',
        "agent_instruction",
        "SKILL.md",
    )

    assert any(
        f.pattern_id == "uvx-execution"
        and f.extracted_dep == "git+https://github.com/microsoft/benchmark-qed"
        for f in findings
    )


def test_uvx_execution_ignores_printed_from_hint_without_substitution():
    findings = scan('echo "uvx --from shellcheck-py shellcheck --version"\n', "script")

    assert not any(f.pattern_id == "uvx-execution" for f in findings)


def test_uvx_execution_ignores_powershell_command_argument_mentions():
    findings = scan(
        "if (-not (Get-Command uvx -ErrorAction SilentlyContinue)) { function global:uvx { } }\n"
        "Remove-Item -Path 'Function:\\uvx' -Force -ErrorAction SilentlyContinue\n"
        "Should -Invoke uvx -Times 1\n",
        "script",
        "Invoke-PipAudit.Tests.ps1",
    )

    assert not any(f.pattern_id == "uvx-execution" for f in findings)


def test_pnpx_execution_detects_script_package_runner():
    findings = scan("pnpx pkg-pr-new publish --pnpm\n", "script", "pkg-pr-new.sh")

    assert any(
        f.pattern_id == "pnpx-execution"
        and f.extracted_dep == "pkg-pr-new"
        for f in findings
    )


def test_pnpx_execution_detects_typescript_execsync_shell_command():
    findings = scan(
        "import { execSync } from 'child_process';\n"
        "execSync(`pnpx pkg-pr-new publish ${modifiedPaths.join(' ')} --pnpm`, { stdio: 'inherit' });\n",
        "source_code",
        "eng/tsp-core/pkg-pr-new.ts",
    )

    assert any(
        f.pattern_id == "pnpx-execution"
        and f.extracted_dep == "pkg-pr-new"
        and f.line_number == 2
        for f in findings
    )


def test_pnpx_execution_ignores_typescript_test_shell_command():
    findings = scan(
        "import { execSync } from 'child_process';\n"
        "execSync('pnpx fixture-package --help');\n",
        "source_code",
        "tests/unit/pkg-pr-new.test.ts",
    )

    assert not any(f.pattern_id == "pnpx-execution" for f in findings)


def test_npx_execution_detects_typescript_exec_shell_command():
    findings = scan(
        "import { ChildProcess } from './childProcess';\n"
        "const res = await new ChildProcess().exec('npx expo-doctor', { cwd: projectRootPath });\n",
        "source_code",
        "src/extension/commands/expoDoctor.ts",
    )

    assert any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "expo-doctor"
        and f.line_number == 2
        for f in findings
    )


def test_npx_execution_detects_typescript_template_exec_shell_command():
    findings = scan(
        "import { ChildProcess } from './childProcess';\n"
        "const res = await new ChildProcess().exec(`npx kill-port ${value}`);\n",
        "source_code",
        "src/extension/commands/killPort.ts",
    )

    assert any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "kill-port"
        and f.line_number == 2
        for f in findings
    )


def test_npx_execution_ignores_typescript_test_shell_command():
    findings = scan(
        "import { exec } from 'child_process';\n"
        "exec('npx kill-port 8081');\n",
        "source_code",
        "test/extension/commands/killPort.test.ts",
    )

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_npx_execution_ignores_javascript_unittests_shell_command():
    findings = scan(
        "const { execSync } = require('child_process');\n"
        "execSync(`npx tsc generated/dom.generated.d.ts --noEmit`);\n",
        "source_code",
        "unittests/index.js",
    )

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_npx_execution_ignores_offline_javascript_shell_command():
    findings = scan(
        "const { execSync } = require('child_process');\n"
        "execSync('npx --offline node-gyp configure -- -f compile_commands_json');\n",
        "source_code",
        "scripts/gen-compile-commands.js",
    )

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_npm_direct_install_detects_javascript_execsync_dynamic_package_prefix():
    findings = scan(
        "const child_process = require('child_process');\n"
        "child_process.execSync(`npm install pxt-${n} ${t ? `--tag ${t}` : ''}`, { stdio: 'inherit' });\n",
        "source_code",
        "pxt-cli/cli.js",
    )

    assert any(
        f.pattern_id == "npm-direct-install"
        and f.extracted_dep == "pxt-${n}"
        and f.line_number == 2
        for f in findings
    )


def test_npm_direct_install_ignores_bare_javascript_shell_install():
    findings = scan(
        "const { execSync } = require('child_process');\n"
        "execSync('npm install');\n"
        "execSync(`cd ${app.name} && npm install --no-update-notifier && cd ..`);\n",
        "source_code",
        "scripts/npm-prepare.js",
    )

    assert not any(f.pattern_id == "npm-direct-install" for f in findings)


def test_npm_direct_install_ignores_fully_dynamic_javascript_shell_package():
    findings = scan(
        "const { execSync } = require('child_process');\n"
        "execSync(`npm install ${platformPackageName}@${packageVersion}`);\n",
        "source_code",
        "eng/npm/wrapper/index.js",
    )

    assert not any(f.pattern_id == "npm-direct-install" for f in findings)


def test_javascript_source_shell_detects_variable_install_commands():
    findings = scan(
        "let command = '';\n"
        "if (platform === 'darwin') {\n"
        "  command = 'brew install node';\n"
        "} else if (platform === 'win32') {\n"
        "  command = 'winget install --id=OpenJS.NodeJS -e';\n"
        "}\n"
        "await executeInTerminal(command, 'NPM Installation');\n",
        "source_code",
        "bdd_ai_toolkit/src/setup/environment.ts",
    )

    rows = {
        (f.pattern_id, f.extracted_dep, f.line_number)
        for f in findings
        if f.pattern_id in {"brew-install-ci", "winget-command-install"}
    }
    assert rows == {
        ("brew-install-ci", "node", 3),
        ("winget-command-install", "OpenJS.NodeJS", 5),
    }


def test_javascript_source_shell_detects_uv_tool_install_command_builder_variable():
    findings = scan(
        "const keyringInstallCommand = getUvPathCommand(\n"
        '  "uv tool install keyring --with artifacts-keyring"\n'
        ");\n"
        'return executeInTerminal(keyringInstallCommand, "UV Keyring Installation");\n',
        "source_code",
        "bdd_ai_toolkit/src/setup/uv.ts",
    )

    assert any(
        f.pattern_id == "uv-tool-install"
        and f.extracted_dep == "keyring"
        and f.line_number == 2
        for f in findings
    )


def test_javascript_source_shell_ignores_unexecuted_install_command_string():
    findings = scan(
        "const command = 'brew install node';\n"
        "console.log(command);\n",
        "source_code",
        "src/setup/environment.ts",
    )

    assert not any(
        f.pattern_id in {"brew-install-ci", "winget-command-install"}
        for f in findings
    )


def test_javascript_source_shell_detects_npm_global_install_arg_array():
    findings = scan(
        "const resolvedNpm = await utils.resolveCommandPath('npm');\n"
        "const { executable: npmExe, prefixArgs: npmArgs } = resolvedNpm\n"
        "  ? await resolveScriptExecutable(resolvedNpm)\n"
        "  : { executable: 'npm', prefixArgs: [] };\n"
        "await this.runStreamedCommand(npmExe, [...npmArgs, 'install', 'autorest', '-g']);\n",
        "source_code",
        "extensions/sql-database-projects/src/tools/autorestHelper.ts",
    )

    assert any(
        f.pattern_id == "npm-global-install"
        and f.extracted_dep == "autorest"
        and f.line_number == 5
        for f in findings
    )
    assert not any(
        f.pattern_id == "npm-direct-install"
        and f.extracted_dep == "autorest"
        for f in findings
    )


def test_javascript_source_shell_ignores_bare_npm_install_arg_array():
    findings = scan(
        "import cp from 'child_process';\n"
        "cp.spawnSync('npm', ['install'], { cwd: targetDir, stdio: 'inherit' });\n",
        "source_code",
        "packages/cli/src/commands/project/new/typescript.ts",
    )

    assert not any(
        f.pattern_id in {"npm-global-install", "npm-direct-install"}
        for f in findings
    )


def test_javascript_source_shell_detects_brew_install_arg_array():
    findings = scan(
        "import { spawnSync } from 'child_process';\n"
        "const result = spawnSync('brew', ['install', 'copilot-cli'], { stdio: 'inherit', env });\n",
        "source_code",
        "extensions/copilot/src/extension/chatSessions/vscode-node/copilotCLIShim.ts",
    )

    assert any(
        f.pattern_id == "brew-install-ci"
        and f.extracted_dep == "copilot-cli"
        and f.line_number == 2
        for f in findings
    )


def test_javascript_source_shell_ignores_non_install_brew_arg_array():
    findings = scan(
        "import { spawnSync } from 'child_process';\n"
        "spawnSync('brew', ['list', 'copilot-cli'], { stdio: 'inherit' });\n",
        "source_code",
        "scripts/check-tools.ts",
    )

    assert not any(f.pattern_id == "brew-install-ci" for f in findings)


def test_python_source_shell_detects_pip_install_arg_array():
    findings = scan(
        "import subprocess\n"
        "import sys\n"
        "subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet', '--no-cache-dir', 'pdfplumber==0.11.4'])\n",
        "source_code",
        "agents/gwp-predictor/training/scripts/parse_ipcc_pdfs.py",
    )

    assert any(
        f.pattern_id == "pip-install-ci"
        and f.extracted_dep == "pdfplumber==0.11.4"
        and f.line_number == 3
        for f in findings
    )


def test_python_source_shell_ignores_requirements_pip_arg_array():
    findings = scan(
        "import subprocess\n"
        "subprocess.run(['pip', 'install', '-r', 'requirements.txt'], check=True)\n",
        "source_code",
        "scripts/bootstrap.py",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_python_source_shell_detects_uv_tool_install():
    findings = scan(
        "import os\n"
        'os.system("uv tool install keyring --with artifacts-keyring")\n',
        "source_code",
        "tools/install_keyring.py",
    )

    assert any(
        f.pattern_id == "uv-tool-install"
        and f.extracted_dep == "keyring"
        and f.line_number == 2
        for f in findings
    )


def test_python_source_shell_ignores_test_path_pip_arg_array():
    findings = scan(
        "import subprocess\n"
        "import sys\n"
        "subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'optuna>=2.8.0,<=3.6.1'])\n",
        "source_code",
        "test/tune/test_searcher.py",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_uv_tool_install_keeps_git_url_package():
    findings = scan(
        "uv tool install git+https://github.com/yourorg/your-tool\n",
        "agent_instruction",
        "SKILL.md",
    )

    assert any(
        f.pattern_id == "uv-tool-install"
        and f.extracted_dep == "git+https://github.com/yourorg/your-tool"
        for f in findings
    )


def test_uv_tool_install_detects_flags_before_git_url_package():
    findings = scan(
        "uv tool install --reinstall --force git+https://github.com/microsoft/conductor.git@branch-name\n",
        "script",
    )

    assert any(
        f.pattern_id == "uv-tool-install"
        and f.extracted_dep == "git+https://github.com/microsoft/conductor.git@branch-name"
        for f in findings
    )


def test_uv_tool_install_detects_versioned_extras_and_skips_option_values():
    findings = scan(
        'uv tool install bc-eval[capi]==0.3.6 --python 3.12 '
        '--index "https://pkgs.example.invalid/feed/pypi/simple/" --with artifacts-keyring\n'
        "uv tool install --python ${{ matrix.python }} --with tox-uv tox\n",
        "ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "uv-tool-install"
    }
    assert deps == {"bc-eval[capi]==0.3.6", "tox"}


def test_uv_tool_install_detects_package_from_git_source_option():
    findings = scan(
        "uv tool install --from "
        '"git+https://github.com/microsoft/RPG-ZeroRepo.git#subdirectory=CoderMind" cmind-cli\n',
        "agent_instruction",
        "SKILL.md",
    )

    assert any(
        f.pattern_id == "uv-tool-install"
        and f.extracted_dep == "cmind-cli"
        for f in findings
    )


def test_uv_tool_install_ignores_local_from_source():
    findings = scan(
        "uv tool install --refresh --from . amplifier-agent\n",
        "agent_instruction",
        "AGENTS.md",
    )

    assert not any(f.pattern_id == "uv-tool-install" for f in findings)


def test_conda_custom_channel_detects_multiple_conda_mamba_channels():
    findings = scan(
        "conda install pytorch==2.4.0 torchvision -c pytorch -c nvidia\n"
        "RUN mamba install -y -c conda-forge -c pyg torch-geometric \\\n"
        "    pytorch-scatter\n"
        "micromamba create -n env --channel conda-forge python=3.11\n",
        "dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "conda-custom-channel"
    }
    assert deps == {"pytorch", "nvidia", "conda-forge", "pyg"}


def test_conda_custom_channel_detects_channel_on_continuation():
    findings = scan(
        "RUN conda install -y \\\n"
        "    -c conda-forge \\\n"
        "    lammps openmpi\n",
        "dockerfile",
    )

    assert any(
        f.pattern_id == "conda-custom-channel"
        and f.extracted_dep == "conda-forge"
        for f in findings
    )


def test_conda_custom_channel_suppresses_defaults_comments_and_hints():
    findings = scan(
        "# conda install -c conda-forge pdbfixer\n"
        'echo "conda install -c conda-forge pdbfixer"\n'
        "conda install -c defaults python\n"
        "conda install -c conda-forge openmm\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "conda-custom-channel"
    }
    assert deps == {"conda-forge"}


def test_conda_custom_channel_ignores_non_control_markdown_example():
    findings = scan(
        "Install dependencies:\n\n"
        "```bash\n"
        "conda install -c conda-forge pdbfixer\n"
        "```\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "conda-custom-channel" for f in findings)


def test_detects_npm_global_install_in_dockerfile():
    findings = scan("RUN npm i @agent-infra/mcp-server-browser@latest -g\n", "dockerfile")

    assert any(
        f.pattern_id == "npm-global-install-flag-after" and f.severity == Severity.CRITICAL
        for f in findings
    )
    assert not any(f.pattern_id == "npm-direct-install" for f in findings)


def test_npm_global_install_skips_flags_before_package():
    findings = scan(
        'npm install --global --force --registry "$NPM_REGISTRY" '
        '"corepack@$CorepackVersion" "@typescript/native-preview@${TSGO_VERSION}"\n',
        "ci",
    )

    assert any(
        f.pattern_id == "npm-global-install"
        and f.extracted_dep == "corepack@$CorepackVersion"
        for f in findings
    )
    assert any(
        f.pattern_id == "npm-global-install"
        and f.extracted_dep == "@typescript/native-preview@${TSGO_VERSION}"
        for f in findings
    )
    assert not any(
        f.pattern_id == "npm-global-install"
        and f.extracted_dep.startswith("--")
        for f in findings
    )


def test_npm_global_install_flag_after_skips_options_before_package():
    findings = scan("npm install --ignore-scripts --global cspell@8.17.3\n", "ci")

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-global-install-flag-after"
    }
    assert deps == {"cspell@8.17.3"}


def test_npm_global_install_keeps_variable_package_name():
    findings = scan("npm install -g $PACKAGE\n", "script")

    assert any(
        f.pattern_id == "npm-global-install"
        and f.extracted_dep == "$PACKAGE"
        for f in findings
    )


def test_npm_global_install_keeps_github_expression_version():
    findings = scan("run: npm install --global npm@${{ matrix.npm }}\n", "ci")

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-global-install"
    }
    assert deps == {"npm@${{ matrix.npm }}"}


def test_npm_global_install_ignores_printed_update_hint():
    findings = scan(
        'log_info "Please update npm with: npm install -g npm@latest"\n'
        'Write-Info "Please update npm with: npm install -g npm@latest"\n'
        "npm install -g real-package\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-global-install"
    }
    assert deps == {"real-package"}


def test_npm_global_install_inline_code_placeholder_does_not_consume_prose():
    findings = scan(
        "Use `npm install -g corepack@<version>` from the configured registry and seed.\n",
        "agent_instruction",
        "SKILL.md",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-global-install"
    }
    assert deps == set()


def test_npm_global_install_inline_code_reports_valid_package_before_prose():
    findings = scan(
        "Use `npm install -g corepack@1.2.3` from the configured registry.\n",
        "agent_instruction",
        "SKILL.md",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-global-install"
    }
    assert deps == {"corepack@1.2.3"}


def test_r_install_packages_reports_each_literal_package():
    findings = scan(
        'install.packages(c("remotes", "stringi"), repos = "https://packagemanager.posit.co/cran/latest")\n',
        "ci",
        "pkgdown.yaml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "r-install-packages"
    }
    assert deps == {"remotes", "stringi"}
    assert "https://packagemanager.posit.co/cran/latest" not in deps


def test_r_install_github_reports_literal_repo_url():
    findings = scan(
        'remotes::install_github("https://github.com/microsoft/finnts")\n',
        "ci",
        "pkgdown.yaml",
    )

    assert any(
        f.pattern_id == "r-install-github"
        and f.extracted_dep == "https://github.com/microsoft/finnts"
        for f in findings
    )


def test_r_install_github_reports_repo_shorthand():
    findings = scan(
        'devtools::install_github(c("r-lib/remotes", "tidyverse/ggplot2@v3.5.0"))\n',
        "github_action",
        "action.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "r-install-github"
    }
    assert deps == {"r-lib/remotes", "tidyverse/ggplot2@v3.5.0"}


def test_r_install_packages_ignores_printed_hint():
    findings = scan('echo "install.packages(\\"pkgdown\\")"\n', "script")

    assert not any(f.pattern_id.startswith("r-install-") for f in findings)


def test_julia_pkg_add_resolves_nearby_name_assignment_in_workflow():
    findings = scan(
        "name: CompatHelper\n"
        "jobs:\n"
        "  CompatHelper:\n"
        "    steps:\n"
        "      - name: Install CompatHelper\n"
        "        run: |\n"
        "          import Pkg\n"
        '          name = "CompatHelper"\n'
        '          uuid = "aa819f21-2bde-4658-8897-bab36330d9b7"\n'
        '          version = "3"\n'
        "          Pkg.add(; name, uuid, version)\n"
        "        shell: julia --color=yes {0}\n",
        "ci",
        ".github/workflows/CompatHelper.yml",
    )

    assert any(
        f.pattern_id == "julia-pkg-add"
        and f.extracted_dep == "CompatHelper"
        for f in findings
    )


def test_julia_pkg_add_detects_direct_package_name():
    findings = scan(
        'julia -e \'import Pkg; Pkg.add("CompatHelper")\'\n',
        "script",
        "install-compathelper.sh",
    )

    assert any(
        f.pattern_id == "julia-pkg-add"
        and f.extracted_dep == "CompatHelper"
        for f in findings
    )


def test_julia_pkg_add_ignores_comments_printed_hints_and_dynamic_only():
    findings = scan(
        '# Pkg.add("Commented")\n'
        'echo "Pkg.add(\\"Printed\\")"\n'
        "Pkg.add(name)\n",
        "script",
        "install-julia.sh",
    )

    assert not any(f.pattern_id == "julia-pkg-add" for f in findings)


def test_pip_direct_url_stops_at_closing_quote():
    findings = scan('pip install "https://github.com/example/tool/archive/v1.0.zip"\n', "ci")

    assert any(
        f.pattern_id == "pip-install-url"
        and f.extracted_dep == "https://github.com/example/tool/archive/v1.0.zip"
        for f in findings
    )


def test_pip_direct_url_ignores_git_plus_https_dependency():
    findings = scan("pip install git+https://github.com/example/dev-utils.git\n", "ci")

    assert not any(f.pattern_id == "pip-install-url" for f in findings)


def test_pip_direct_url_ignores_comments_and_hints():
    findings = scan(
        "# pip install https://github.com/example/commented/archive/v1.zip\n"
        'echo "pip install https://github.com/example/hint/archive/v1.zip"\n'
        "pip install https://github.com/example/real/archive/v1.zip\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-url"
    }
    assert deps == {"https://github.com/example/real/archive/v1.zip"}


def test_pip_direct_url_does_not_cross_shell_command_separator():
    findings = scan(
        'pip install uv && uvx --from "https://github.com/microsoft/benchmark-qed/archive/main.zip" benchmark-qed\n',
        "agent_instruction",
        "SKILL.md",
    )

    assert not any(
        f.pattern_id == "pip-install-url"
        and f.extracted_dep == "https://github.com/microsoft/benchmark-qed/archive/main.zip"
        for f in findings
    )


def test_pip_direct_url_stops_before_shell_case_terminator():
    findings = scan(
        "2.1.0) pip install kaolin -f "
        "https://nvidia-kaolin.s3.us-east-2.amazonaws.com/torch-2.1.0_cu118.html;;\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-url"
    }
    assert deps == {"https://nvidia-kaolin.s3.us-east-2.amazonaws.com/torch-2.1.0_cu118.html"}


def test_uv_pip_index_url_reports_custom_index_not_direct_url():
    index_url = "https://private.example.com/" + ("nested/" * 30) + "simple/"
    findings = scan(
        'uv pip install --python .venv/bin/python "bc-eval[capi]==0.3.7" '
        f'--index "{index_url}"\n',
        "ci",
    )

    assert any(
        f.pattern_id == "pip-custom-index"
        and f.extracted_dep == index_url[:200]
        for f in findings
    )
    assert not any(f.pattern_id == "pip-install-url" for f in findings)


def test_pip_custom_index_detects_dockerfile_index_url():
    findings = scan(
        "RUN pip3 install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu \\\n"
        "    torch==2.2.2\n",
        "dockerfile",
    )

    assert any(
        f.pattern_id == "pip-custom-index"
        and f.extracted_dep == "https://download.pytorch.org/whl/cpu"
        for f in findings
    )


def test_uv_pip_custom_index_reads_continued_extra_index_url():
    findings = scan(
        'uv pip install --no-cache-dir --project "$runtime_project" '
        '--requirement "$runtime_requirements" --index-strategy first-index \\\n'
        "  --extra-index-url https://download.pytorch.org/whl/cu124\n",
        "script",
    )

    assert any(
        f.pattern_id == "pip-custom-index"
        and f.extracted_dep == "https://download.pytorch.org/whl/cu124"
        and f.line_number == 1
        for f in findings
    )


def test_pip_custom_index_ignores_comments_and_printed_hints():
    findings = scan(
        "# pip install --index-url https://download.pytorch.org/whl/cpu torch\n"
        'echo "pip install --index-url https://download.pytorch.org/whl/cpu torch"\n'
        "pip install --index-url https://download.pytorch.org/whl/cu121 torch\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-custom-index"
    }
    assert deps == {"https://download.pytorch.org/whl/cu121"}


def test_pipx_install_keeps_git_https_spec():
    findings = scan(
        "pipx install git+https://github.com/microsoft/conductor.git@branch-name\n",
        "agent_instruction",
        "README.md",
    )

    assert any(
        f.pattern_id == "pipx-install"
        and f.extracted_dep == "git+https://github.com/microsoft/conductor.git@branch-name"
        for f in findings
    )
    assert not any(
        f.pattern_id == "pipx-install"
        and f.extracted_dep == "git"
        for f in findings
    )


def test_detects_npx_execution_in_dockerfile():
    findings = scan("RUN npx puppeteer browsers install chrome --install-deps\n", "dockerfile")

    assert any(f.pattern_id == "npx-execution" for f in findings)


def test_detects_npx_execution_in_composite_action():
    findings = scan("runs:\n  using: composite\n  steps:\n    - run: npx lerna publish\n", "github_action")

    assert any(f.pattern_id == "npx-execution" and f.extracted_dep == "lerna" for f in findings)


def test_detects_npx_execution_in_agent_instruction():
    findings = scan("Run: npx skills add acme-co/agent-skills --skill swe-agent\n", "agent_instruction")

    assert any(f.pattern_id == "npx-execution" and f.extracted_dep == "skills" for f in findings)


def test_detects_npm_create_in_control_agent_instruction():
    findings = scan(
        "npm create vite@latest my-app -- --template react-ts\n",
        "agent_instruction",
        "SKILL.md",
    )

    assert any(
        f.pattern_id == "npm-create"
        and f.extracted_dep == "vite@latest"
        and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_npm_create_ignores_non_control_markdown_inline_example():
    findings = scan(
        "Do not use `git clone`, `npm create vite@latest`, or manual file creation.\n",
        "agent_instruction",
        "code-app-architect.md",
    )

    assert not any(f.pattern_id == "npm-create" for f in findings)


def test_npm_create_ignores_do_not_use_prose():
    findings = scan(
        "Always use npx degit; do not use npm create vite@latest for scaffolding.\n",
        "agent_instruction",
        "SKILL.md",
    )

    assert not any(f.pattern_id == "npm-create" for f in findings)


def test_npx_execution_skips_uppercase_npx_cli_acronym_before_command():
    findings = scan(
        "Apps are deployed via the Power Apps NPX CLI (`npx power-apps push`).\n",
        "agent_instruction",
    )

    npx_findings = [f for f in findings if f.pattern_id == "npx-execution"]
    assert [f.extracted_dep for f in npx_findings] == ["power-apps"]


def test_ignores_agent_allowed_tools_metadata_for_npx_execution():
    findings = scan(
        "---\nallowed-tools: Bash(link-cli:*), Bash(npx:*), Bash(npm:*)\n---\n",
        "agent_instruction",
        "SKILL.md",
    )

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_ignores_npx_when_listed_in_shell_for_loop():
    findings = scan('for tool in npx node jq; do command -v "$tool"; done\n')

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_ignores_npx_in_powershell_comments_and_output_strings():
    findings = scan(
        "BuildArgs = $null  # built via npx run-windows manually\n"
        'Write-Host "[skip] Build first with \'npx run-windows\'."\n'
        'if (-not $npx -or -not $npm) { throw "npm/npx not on PATH" }\n'
        '"npx @react-native-community/cli run-windows" | Tee-Object -FilePath $log\n'
        "npx lerna publish\n",
        "script",
        "run_startup_bench.ps1",
    )

    npx_findings = [f for f in findings if f.pattern_id == "npx-execution"]
    assert len(npx_findings) == 1
    assert npx_findings[0].extracted_dep == "lerna"


def test_ignores_npx_inside_javascript_console_output_string():
    findings = scan(
        '  "postinstall": "node -e \\"console.log(\\\'Get started with: npx winapp --help\\\')\\"",\n',
        "package_config",
        "package.json",
    )

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_ignores_npx_in_batch_echo_and_commit_messages():
    findings = scan(
        "@echo Creating app with: npx --yes @react-native-community/cli init App\n"
        'call git commit -m "npx --yes @react-native-community/cli init App"\n'
        "call npx --yes @react-native-community/cli init App\n",
        "script",
        "creaternwapp.cmd",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npx-execution"
    ]
    assert deps == ["@react-native-community/cli"]


def test_ignores_npx_in_prose_sentences():
    findings = scan(
        "These are the only correct configurations. Do not use stdio/npx for HTTP servers.\n"
        "Checks if vsce or npx is available for packaging.\n"
        "It 'Returns npx when only npx command is found' {\n"
        "Abstracts platform-specific execution of vsce/npx commands.\n"
        "npx vally eval --eval-spec evals/agent-behavior/eval.yaml\n",
        "script",
        "Package-Extension.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npx-execution"
    }
    assert deps == {"vally"}


def test_ignores_npx_cache_prose_sentence():
    findings = scan(
        "The first invocation downloads @playwright/cli@0.1.1 into the npx cache; "
        "subsequent calls are cached.\n"
        "npx -y @playwright/cli@0.1.1 snapshot\n",
        "agent_instruction",
        "SKILL.md",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npx-execution"
    ]
    assert deps == ["@playwright/cli@0.1.1"]


def test_ignores_npx_in_markdown_fence_metadata():
    findings = scan(
        '```bash title="skills.sh NPX with explicit target"\n'
        "npx skills add acme-co/agent-skills\n"
        "```\n",
        "agent_instruction",
        "SKILL.md",
    )

    npx_findings = [f for f in findings if f.pattern_id == "npx-execution"]
    assert len(npx_findings) == 1
    assert npx_findings[0].line_number == 2
    assert npx_findings[0].extracted_dep == "skills"


def test_detects_npx_package_option_in_workflow():
    findings = scan(
        "run: npx --package=@vscode/telemetry-extractor@1.14.0 --yes telemetry-extractor\n",
        "ci",
    )

    assert any(
        f.pattern_id == "npx-package-execution"
        and f.extracted_dep == "@vscode/telemetry-extractor@1.14.0"
        for f in findings
    )


def test_detects_multiple_npx_package_options():
    findings = scan(
        "npx --package yo --package generator-code -- yo code\n",
        "agent_instruction",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npx-package-execution"
    }
    assert {"yo", "generator-code"} <= deps


def test_npx_package_option_ignores_command_flags_after_package():
    findings = scan(
        "npx http-server _serve -p 4000 -s &\n",
        "ci",
    )

    assert not any(f.pattern_id == "npx-package-execution" for f in findings)
    assert any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "http-server"
        for f in findings
    )


def test_npx_execution_ignores_plain_markdown_prose_words():
    findings = scan(
        "- [NPX Live Tests](#npx-live-tests)\n"
        "No external npm/npx dependency is needed.\n"
        "Use the classic npx route via `.vscode/mcp.json`.\n"
        "Fixed passing args through an npx call to the CLI.\n"
        "PackageMCPB includes standalone binaries, npm/npx, and NuGet packages.\n"
        + ("Release metadata " * 20) + "always creates the npm/npx and NuGet artifacts.\n"
        "Fail install to prevent npx caching of `@azure/mcp`.\n"
        "npx -y clear-npx-cache\n",
        "agent_instruction",
        "README.md",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npx-execution"
    }
    assert deps == {"clear-npx-cache"}


def test_npx_execution_ignores_failed_connection_prose():
    findings = scan(
        "- Or the MCP server may fail silently with `npx failed to connect to azure`\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_npx_execution_ignores_quoted_research_prompt_text():
    findings = scan(
        'Deep Research prompt:\n\n'
        '"Write a micro expert defining a Teams SDK TypeScript bot project. '
        'Cover CLI scaffolding with npx @microsoft/teams.cli and build verification with npx tsc --noEmit. '
        'Include the full package.json template."\n',
        "agent_instruction",
        ".github/plugins/microsoft-365-agents-toolkit/skills/teams-app-developer/experts/teams/project.scaffold-files-ts.md",
    )

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_npx_execution_keeps_agent_instruction_prose_command():
    findings = scan(
        "- Check that the code builds by running npx hereby build in the terminal.\n",
        "agent_instruction",
        ".github/agents/strada-corsa-port.md",
    )

    assert any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "hereby"
        for f in findings
    )


def test_uvx_execution_ignores_plain_markdown_prose_words():
    findings = scan(
        "- Added UVX support for Python workflows.\n"
        "**When to use uvx vs pipx vs pip:**\n"
        "uvx msmcp-azure server start\n",
        "agent_instruction",
        "README.md",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "uvx-execution"
    }
    assert deps == {"msmcp-azure"}


def test_uvx_execution_ignores_non_control_markdown_from_example():
    findings = scan(
        'Run `uvx --from "git+https://github.com/microsoft/RPG-ZeroRepo.git#subdirectory=CoderMind" cmind init app`.\n',
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "uvx-execution" for f in findings)


def test_detects_npx_package_option_in_package_json_script():
    findings = scan(
        """{
  "scripts": {
    "extract": "npx --package=@vscode/telemetry-extractor --yes telemetry-extractor"
  }
}
""",
        "package_config",
        "package.json",
    )

    assert any(
        f.pattern_id == "npx-package-execution"
        and f.extracted_dep == "@vscode/telemetry-extractor"
        for f in findings
    )


def test_detects_npm_exec_package_option_in_package_json_script():
    findings = scan(
        """{
  "scripts": {
    "decks:build": "npm exec --package=@marp-team/marp-cli -- marp -I decks --pdf"
  }
}
""",
        "package_config",
        "package.json",
    )

    assert any(
        f.pattern_id == "npm-exec-package"
        and f.extracted_dep == "@marp-team/marp-cli"
        for f in findings
    )


def test_detects_npm_exec_multiple_package_options():
    findings = scan(
        "npm exec --package yo -p generator-code -- yo code\n",
        "ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-exec-package"
    }
    assert deps == {"yo", "generator-code"}


def test_npm_exec_plain_local_command_is_not_shadow_download():
    findings = scan(
        'npm exec -- npm-run-all2 -lp "electron ${{ env.VSCODE_ARCH }}" "playwright-install"\n',
        "ci",
    )

    assert not any(f.pattern_id == "npm-exec-package" for f in findings)


def test_npm_exec_package_ignores_printed_guidance():
    findings = scan(
        'echo "npm exec --package @marp-team/marp-cli -- marp"\n'
        "npm exec --package real-tool -- real-tool\n",
        "script",
        "setup.sh",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-exec-package"
    ]
    assert deps == ["real-tool"]


def test_npm_exec_package_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `npm exec --package npm-check-updates -- npm-check-updates --upgrade` manually.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "npm-exec-package" for f in findings)


def test_package_json_npx_declared_local_bin_is_not_shadow_download():
    findings = scan(
        """{
  "scripts": {
    "e2e": "npx playwright test && npx nyc report"
  },
  "devDependencies": {
    "@playwright/test": "1.58.2",
    "nyc": "^18.0.0"
  }
}
""",
        "package_config",
        "package.json",
    )

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_package_json_npx_undeclared_bin_is_still_reported():
    findings = scan(
        """{
  "scripts": {
    "publish": "npx vsce package"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
""",
        "package_config",
        "package.json",
    )

    assert any(
        f.pattern_id == "npx-execution" and f.extracted_dep == "vsce"
        for f in findings
    )


def test_script_npx_declared_local_bin_is_not_shadow_download(tmp_path):
    package_json = tmp_path / "package.json"
    package_json.write_text(
        """{
  "devDependencies": {
    "gulp": "5.0.0"
  }
}
""",
        encoding="utf-8",
    )
    hook = tmp_path / ".husky" / "pre-commit"
    hook.parent.mkdir()
    hook.write_text("#!/bin/sh\nnpx gulp lint\n", encoding="utf-8")

    scanner = UnmanagedPackageScanner(Config())
    target = FileTarget(path=hook, rel_path=".husky/pre-commit", file_type="script")
    findings = scanner.scan_file(target)

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_script_npx_without_local_package_is_still_reported(tmp_path):
    package_json = tmp_path / "package.json"
    package_json.write_text(
        """{
  "devDependencies": {
    "typescript": "5.8.0"
  }
}
""",
        encoding="utf-8",
    )
    hook = tmp_path / ".husky" / "pre-commit"
    hook.parent.mkdir()
    hook.write_text("#!/bin/sh\nnpx gulp lint\n", encoding="utf-8")

    scanner = UnmanagedPackageScanner(Config())
    target = FileTarget(path=hook, rel_path=".husky/pre-commit", file_type="script")
    findings = scanner.scan_file(target)

    assert any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "gulp"
        for f in findings
    )


def test_workflow_npx_uses_working_directory_package_json(tmp_path):
    package_json = tmp_path / "frontend" / "package.json"
    package_json.parent.mkdir()
    package_json.write_text(
        """{
  "devDependencies": {
    "@playwright/test": "1.61.1",
    "typescript": "6.0.3"
  }
}
""",
        encoding="utf-8",
    )
    workflow = tmp_path / ".github" / "workflows" / "frontend.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "jobs:\n"
        "  e2e:\n"
        "    defaults:\n"
        "      run:\n"
        "        working-directory: frontend\n"
        "    steps:\n"
        "      - run: npm ci\n"
        "      - run: npx playwright install --with-deps chromium\n"
        "      - run: npx playwright test --project=mock\n"
        "  lint:\n"
        "    defaults:\n"
        "      run:\n"
        "        working-directory: frontend\n"
        "    steps:\n"
        "      - run: npm ci\n"
        "      - run: npx tsc --noEmit\n",
        encoding="utf-8",
    )

    scanner = UnmanagedPackageScanner(Config())
    target = FileTarget(
        path=workflow,
        rel_path=".github/workflows/frontend.yml",
        file_type="ci",
    )
    findings = scanner.scan_file(target)

    assert not any(f.pattern_id == "npx-execution" for f in findings)


def test_detects_direct_npm_package_install_in_dockerfile():
    findings = scan("RUN npm install puppeteer puppeteer-core @puppeteer/browsers\n", "dockerfile")

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-direct-install"
    }
    assert {"puppeteer", "puppeteer-core", "@puppeteer/browsers"} <= deps


def test_npm_direct_install_reports_each_named_agent_instruction_package():
    findings = scan(
        "npm install vega vega-lite vega-embed  # browser Vega-Lite rendering\n",
        "agent_instruction",
        "SKILL.md",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-direct-install"
    }
    assert deps == {"vega", "vega-lite", "vega-embed"}


def test_npm_direct_install_stops_before_parenthetical_note():
    findings = scan(
        "// Install: npm install jimp (in a temp directory)\n",
        "agent_instruction",
        "mcp-plugin.md",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "npm-direct-install"
    ]
    assert deps == ["jimp"]


def test_npm_direct_install_ignores_ellipsis_placeholder_package():
    findings = scan(
        "{ title: 'Getting Started', content: 'Install the SDK with npm install @microsoft/teams.ai...' },\n",
        "agent_instruction",
        "ai.rag-retrieval-ts.md",
    )

    assert not any(f.pattern_id == "npm-direct-install" for f in findings)


def test_ignores_prose_npm_install_is_allowed():
    findings = scan("✓ Npm install is an allowed command\n", "agent_instruction", "README.md")

    assert not any(f.pattern_id == "npm-direct-install" for f in findings)


def test_ignores_markdown_image_alt_text_install_mentions():
    findings = scan(
        "![Screenshot of the terminal showing npm install candy is run by the agent.](terminal.png)\n",
        "agent_instruction",
        "release-notes.md",
    )

    assert not any(f.pattern_id == "npm-direct-install" for f in findings)


def test_keeps_npm_install_package_named_is():
    findings = scan("RUN npm install is && npm test\n", "dockerfile")

    assert any(
        f.pattern_id == "npm-direct-install" and f.extracted_dep == "is"
        for f in findings
    )


def test_ignores_bare_npm_install_in_dockerfile():
    findings = scan("RUN cd js && npm install && npm run build\n", "dockerfile")

    assert not any(f.pattern_id == "npm-direct-install" for f in findings)


def test_npm_direct_install_ignores_redirection_after_bare_install():
    findings = scan(
        'if (Test-Path "package.json") { npm install 2>$null }\n',
        "ci",
        "samples-integration-test.yml",
    )

    assert not any(f.pattern_id == "npm-direct-install" for f in findings)


def test_npm_direct_install_ignores_production_flag_before_chained_command():
    findings = scan(
        "run: cd ./.github/actions && npm install --production && cd ../..\n",
        "ci",
        "workflow.yml",
    )

    assert not any(f.pattern_id == "npm-direct-install" for f in findings)


def test_npm_direct_install_keeps_package_after_boolean_flag():
    findings = scan(
        "npm install --no-save node-gyp node-api-headers --registry https://registry.npmjs.org\n",
        "ci",
    )

    assert any(
        f.pattern_id == "npm-direct-install"
        and f.extracted_dep == "node-api-headers"
        for f in findings
    )


def test_pip_install_ci_reports_each_named_package_and_skips_local_artifacts():
    findings = scan(
        "RUN pip install --no-cache-dir *.whl pytest python-dotenv azure-identity\n",
        "dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert {"pytest", "python-dotenv", "azure-identity"} <= deps
    assert "*.whl" not in deps


def test_pip_install_ci_reports_comparison_version_specs():
    findings = scan(
        'RUN pip install --no-cache-dir -q "numpy<2.0" pandas '
        '"ase<=3.25.0" "jaraco.context>=6.1.0"\n',
        "dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert {"numpy<2.0", "pandas", "ase<=3.25.0", "jaraco.context>=6.1.0"} <= deps


def test_pip_install_ci_reports_comma_separated_version_ranges():
    findings = scan(
        "python -m pip install \\\n"
        '    "pydantic>=2.5.0,<3.0" \\\n'
        '    "pyyaml>=6.0,<7.0"\n',
        "dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert deps == {"pydantic>=2.5.0,<3.0", "pyyaml>=6.0,<7.0"}


def test_pip_install_ci_reports_only_comparison_spec_after_boolean_flag():
    findings = scan('RUN pip install -q "numpy<2.0"\n', "dockerfile")

    assert any(
        f.pattern_id == "pip-install-ci"
        and f.extracted_dep == "numpy<2.0"
        for f in findings
    )


def test_pip_install_ci_keeps_github_expression_version_with_package():
    findings = scan(
        "pip install pyright==${{ steps.pyright-version.outputs.version }}\n",
        "ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert deps == {"pyright==${{steps.pyright-version.outputs.version}}"}


def test_pip_install_ci_keeps_shell_variable_version_with_package():
    findings = scan(
        'python -m pip install --quiet '
        '"agent-governance-toolkit[full]==$AGT_TOOLKIT_VERSION" '
        "sample-lib>=${SAMPLE_LIB_VERSION}\n",
        "github_action",
        "action.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert deps == {
        "agent-governance-toolkit[full]==$AGT_TOOLKIT_VERSION",
        "sample-lib>=${SAMPLE_LIB_VERSION}",
    }


def test_pip_install_ci_ignores_variable_local_wheel_artifact():
    findings = scan('python3 -m pip install "${WHEEL[0]}[test]"\n', "ci")

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_reports_multiline_python_module_install():
    findings = scan(
        "if ! python3 -m pip install \\\n"
        "    black \\\n"
        "    flake8 \\\n"
        "    pytest \\\n"
        "    mypy \\\n"
        "    bandit \\\n"
        "    jupyter \\\n"
        "    jupyterlab \\\n"
        "    ipykernel; then\n"
        "    exit 1\n"
        "fi\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert deps == {
        "black",
        "flake8",
        "pytest",
        "mypy",
        "bandit",
        "jupyter",
        "jupyterlab",
        "ipykernel",
    }


def test_pip_install_ci_multiline_stops_at_shell_command_separator():
    findings = scan(
        "python -m pip install --no-cache-dir -r requirements.txt && \\\n"
        "python -m pip install DeepSpeed\n",
        "script",
    )

    deps_by_line = {
        (f.line_number, f.extracted_dep)
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert deps_by_line == {(2, "DeepSpeed")}


def test_pip_install_ci_ignores_multiline_non_control_markdown_example():
    findings = scan(
        "Install optional tools:\n\n"
        "```bash\n"
        "python3 -m pip install \\\n"
        "    black \\\n"
        "    flake8\n"
        "```\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_versioned_packaging_tool_bootstraps():
    findings = scan(
        'RUN pip install --upgrade "pip>=26.0" setuptools==78.1.1 '
        'wheel>=0.46.2 pip-tools==7.5.0 uv==0.8.0\n',
        "dockerfile",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_local_no_index_find_links_install():
    findings = scan(
        "python3 -m pip install --user --no-index --no-deps "
        "--find-links build/cpu/wheel onnxruntime_genai\n",
        "ci",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_keeps_external_no_index_find_links_install():
    findings = scan(
        "RUN pip install --no-index --find-links https://data.pyg.org/whl "
        "torch_scatter\n",
        "dockerfile",
    )

    assert any(
        f.pattern_id == "pip-install-ci"
        and f.extracted_dep == "torch_scatter"
        for f in findings
    )


def test_pip_install_ci_stops_before_stdout_redirection():
    findings = scan("pip3 install pyodbc >> env_setup.log\n", "script")

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert deps == {"pyodbc"}


def test_pip_install_ci_ignores_requirements_and_local_project_installs():
    findings = scan(
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "RUN pip install -U -r doc/requirements.txt\n"
        "RUN pip install --no-cache-dir .\n",
        "dockerfile",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_github_expression_requirements_path():
    findings = scan(
        "python3 -m pip install --user -r ${{ github.workspace }}/tools/ci_build/requirements.txt\n",
        "ci",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_editable_local_project_after_flags():
    findings = scan("pip install -q -U -e python\n", "ci")

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_stops_before_comments_and_inline_markdown_prose():
    findings = scan(
        "pip install agent-framework-core          # Core only\n"
        "`pip install agent-framework-... --pre` so they use `pip install agent-framework-...` without\n",
        "agent_instruction",
        "SKILL.md",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert deps == {"agent-framework-core"}


def test_pip_install_ci_ignores_inline_release_note_prose():
    findings = scan(
        "You can upgrade coverage by running `pip install coverage==7.7`.\n",
        "agent_instruction",
        "release-notes.md",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_url_ignores_link_after_inline_editable_install_prose():
    findings = scan(
        "Editable mode (`pip install -e .`) as defined by [PEP 660](https://peps.python.org/pep-0660/).\n",
        "agent_instruction",
        "release-notes.md",
    )

    assert not any(f.pattern_id == "pip-install-url" for f in findings)


def test_pip_install_ci_keeps_imperative_inline_command():
    findings = scan(
        "Run `pip install pytest` before invoking the test runner.\n",
        "agent_instruction",
        "SKILL.md",
    )

    assert any(
        f.pattern_id == "pip-install-ci" and f.extracted_dep == "pytest"
        for f in findings
    )


def test_pip_install_ci_keeps_control_doc_table_command_cell():
    findings = scan(
        "| Python SDK and generator | "
        "`python -m pip install ./sdk/python ./generator pytest` then "
        "`pytest sdk/python generator` |\n",
        "agent_instruction",
        "AGENTS.md",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert deps == {"pytest"}


def test_pip_install_ci_ignores_non_control_doc_table_command_cell():
    findings = scan(
        "| Tool | Command |\n"
        "| --- | --- |\n"
        "| Test | `python -m pip install pytest` |\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_inline_hash_comment_mentions():
    findings = scan(
        "qdk                          # top-level package - pip install qdk\n"
        "pip install qdk\n",
        "agent_instruction",
        "python.md",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    }
    assert deps == {"qdk"}


def test_pip_install_ci_ignores_printed_warning_after_requirements_install():
    findings = scan(
        'pip install -r "$REQ_PATH" --quiet 2>/dev/null && '
        'echo "Python dependencies installed." || '
        'echo "WARNING: pip install failed. Run manually: pip install -r requirements.txt"\n',
        "script",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_powershell_printed_failure():
    findings = scan(
        'Write-ErrorText "pip install failed (exit code $pipExitCode)."\n',
        "script",
        "install.ps1",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_stops_before_parenthetical_note():
    findings = scan(
        "pip install orjson   (OPTIONAL - faster JSON parsing; falls back to stdlib json)\n",
        "script",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    ]
    assert deps == ["orjson"]


def test_pip_install_ci_stops_at_printed_powershell_closing_quote():
    findings = scan(
        'Write-LogHost "Fabric: \'deltalake\' install threw: $($_.Exception.Message). '
        'Install manually with \'pip install deltalake\' and re-run." -ForegroundColor Red\n',
        "script",
        "Install.ps1",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    ]
    assert deps == ["deltalake"]


def test_pip_install_ci_ignores_custom_powershell_write_helper():
    findings = scan(
        'Write-Warn2 "pip install returned exit code $pipExit (non-fatal, /setup will retry)"\n',
        "script",
        "Install-EssAdk.ps1",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_powershell_missing_install_hint_storage():
    findings = scan(
        '$missing += "PyYAML - install: pip install pyyaml"\n'
        '& $pipPy.Source -m pip install pyyaml 2>&1 | Out-Null\n',
        "script",
        "Check-Prerequisites.ps1",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-install-ci"
    ]
    assert deps == ["pyyaml"]


def test_pip_install_ci_ignores_powershell_throw_exit_message():
    findings = scan(
        'if ($LASTEXITCODE -ne 0) { throw "pip install exit $LASTEXITCODE" }\n',
        "script",
        "build_and_test_all.ps1",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_package_json_npx_ignores_bin_from_local_file_dependency():
    scanner = UnmanagedPackageScanner(Config())
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        local_pkg = root / "js" / "ccf-app"
        local_pkg.mkdir(parents=True)
        local_pkg.joinpath("package.json").write_text(
            '{"name":"@microsoft/ccf-app","bin":{"ccf-build-bundle":"scripts/build_bundle.js"}}'
        )
        consumer = root / "tests" / "npm-app"
        consumer.mkdir(parents=True)
        package_json = consumer / "package.json"
        package_json.write_text(
            '{\n'
            '  "private": true,\n'
            '  "scripts": {\n'
            '    "bundle": "npx ccf-build-bundle dist",\n'
            '    "external": "npx external-tool"\n'
            '  },\n'
            '  "dependencies": {"@microsoft/ccf-app": "file:../../js/ccf-app"}\n'
            '}\n'
        )
        target = FileTarget(
            path=package_json,
            rel_path="tests/npm-app/package.json",
            file_type="package_config",
        )
        findings = scanner.scan_file(target)

    assert not any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "ccf-build-bundle"
        for f in findings
    )
    assert any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "external-tool"
        for f in findings
    )


def test_package_json_npx_ignores_known_bin_from_declared_dependency():
    findings = scan(
        '{\n'
        '  "scripts": {"release": "npx changeset publish"},\n'
        '  "devDependencies": {"@changesets/cli": "^2.26.2"}\n'
        '}\n',
        "package_config",
        "package.json",
    )

    assert not any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "changeset"
        for f in findings
    )


def test_package_json_npx_ignores_typescript_tsc_bin_from_declared_dependency():
    findings = scan(
        '{\n'
        '  "scripts": {"build:test-unit": "cd tests/unit && npx tsc"},\n'
        '  "devDependencies": {"typescript": "^5.8.0"}\n'
        '}\n',
        "package_config",
        "package.json",
    )

    assert not any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "tsc"
        for f in findings
    )


def test_package_json_npx_ignores_typespec_tsp_bin_from_declared_dependency():
    findings = scan(
        '{\n'
        '  "scripts": {"generate": "npx tsp compile model/main.tsp --config tspconfig.yaml"},\n'
        '  "dependencies": {"@typespec/compiler": "latest"}\n'
        '}\n',
        "package_config",
        "package.json",
    )

    assert not any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "tsp"
        for f in findings
    )


def test_package_json_npx_ignores_vsce_bin_from_declared_dependency():
    findings = scan(
        '{\n'
        '  "scripts": {"pack": "npx vsce package --no-dependencies"},\n'
        '  "devDependencies": {"@vscode/vsce": "^3.9.2"}\n'
        '}\n',
        "package_config",
        "package.json",
    )

    assert not any(
        f.pattern_id == "npx-execution"
        and f.extracted_dep == "vsce"
        for f in findings
    )


def test_detects_dockerfile_system_packages_and_corepack_prepare():
    findings = scan(
        "RUN apt-get update && apt-get install -y wget docker.io jq\n"
        "RUN corepack prepare pnpm@10.0.0 --activate && corepack prepare yarn@4.14.1 --activate\n"
        "RUN corepack install -g pnpm@latest\n",
        "dockerfile",
    )

    system_deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "system-package-install"
    }
    assert {"wget", "docker.io", "jq"} <= system_deps
    deps = {
        f.extracted_dep for f in findings
        if f.pattern_id == "corepack-prepare"
    }
    assert {"pnpm@10.0.0", "yarn@4.14.1"} <= deps
    assert any(
        f.pattern_id == "corepack-install"
        and f.extracted_dep == "pnpm@latest"
        for f in findings
    )


def test_corepack_install_ignores_unversioned_enable_and_guidance():
    findings = scan(
        "corepack enable pnpm\n"
        "corepack install || echo warning\n"
        'echo "corepack install -g pnpm@latest"\n'
        "corepack install --global yarn@4.14.1\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "corepack-install"
    }
    assert deps == {"yarn@4.14.1"}


def test_corepack_install_ignores_non_control_markdown_example():
    findings = scan(
        "Install the package manager with `corepack install -g pnpm@latest`.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "corepack-install" for f in findings)


def test_system_package_install_skips_github_expression_option_value():
    findings = scan(
        "tdnf install --snapshottime=${{ needs.image_digest.outputs.SOURCE_DATE_EPOCH }} -y jq\n",
        "ci",
    )

    assert any(
        f.pattern_id == "system-package-install"
        and f.extracted_dep == "jq"
        for f in findings
    )
    assert not any(
        f.pattern_id == "system-package-install"
        and "SOURCE_DATE_EPOCH" in f.extracted_dep
        for f in findings
    )


def test_system_package_install_ignores_local_artifact_operands():
    findings = scan(
        'apt-get install -y /packages/*.deb\n'
        'find -name "libmsquic*.rpm" -exec dnf install -y --nogpgcheck {} \\;\n'
        'find -name "libmsquic*.apk" -exec apk add --allow-untrusted {} \\;\n'
        "'DEBIAN_FRONTEND=noninteractive apt-get install -y \"$DEB_FILE\"',\n"
        "'    dnf install -y --nogpgcheck --setopt=install_weak_deps=True \"$RPM_FILE\"',\n",
        "ci",
    )

    assert not any(f.pattern_id == "system-package-install" for f in findings)


def test_system_package_install_stops_before_redirection():
    findings = scan(
        "sudo apt-get update -qq && sudo apt-get install -y -qq git 2>/dev/null || brew install git\n",
        "script",
    )

    assert any(
        f.pattern_id == "system-package-install"
        and f.extracted_dep == "git"
        for f in findings
    )
    assert not any(
        f.pattern_id == "system-package-install"
        and f.extracted_dep == "git 2"
        for f in findings
    )


def test_system_package_install_stops_before_stdout_redirection():
    findings = scan(
        "yes | sudo apt-get install git zip curl >> env_setup.log\n"
        "yes | sudo yum install epel-release-latest-7.noarch.rpm >> env_setup.log || true\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "system-package-install"
    }
    assert {"git", "zip", "curl"} <= deps
    assert "git zip curl" not in deps
    assert "git zip curl env_setup.log" not in deps
    assert "env_setup.log" not in deps


def test_system_package_install_stops_before_yaml_step_metadata():
    findings = scan(
        "sudo apt-get install -y gcc-multilib lcov pkg-config libelf-dev "
        "- name: Clone and build libbpf - Ubuntu-22.04\n",
        "ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "system-package-install"
    }
    assert deps == {"gcc-multilib", "lcov", "pkg-config", "libelf-dev"}


def test_system_package_install_ignores_redirected_echo_help():
    findings = scan(
        '>&2 echo "missing $1 - Try \'sudo apt install clang-tools lld llvm-dev\' or check the guide."\n',
        "script",
    )

    assert not any(f.pattern_id == "system-package-install" for f in findings)


def test_add_apt_repository_extracts_url_from_wget_command_substitution():
    findings = scan(
        'sudo add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/20.04/prod.list)"\n',
        "agent_instruction",
        "setup-dev-env.prompt.md",
    )

    assert any(
        f.pattern_id == "add-apt-repository"
        and f.extracted_dep == "https://packages.microsoft.com/config/ubuntu/20.04/prod.list"
        for f in findings
    )


def test_add_apt_repository_keeps_shell_substitution_inside_url():
    url = "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/prod.list"
    findings = scan(
        f'sudo add-apt-repository "$(curl {url})"\n',
        "ci",
        ".github/workflows/deploy.yml",
    )

    assert any(
        f.pattern_id == "add-apt-repository"
        and f.extracted_dep == url
        for f in findings
    )


def test_add_apt_repository_extracts_url_from_quoted_deb_entry():
    findings = scan(
        'sudo add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"\n',
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "add-apt-repository"
    }
    assert deps == {"https://download.docker.com/linux/ubuntu"}


def test_add_apt_repository_ignores_builtin_ubuntu_components():
    findings = scan(
        "add-apt-repository universe\n"
        "add-apt-repository ppa:git-core/ppa\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "add-apt-repository"
    }
    assert deps == {"ppa:git-core/ppa"}


def test_apt_sources_list_write_extracts_repo_url_from_echo_command():
    findings = scan(
        'RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg '
        '| gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg && '
        'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] '
        'https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list\n',
        "dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "apt-sources-list-write"
    }
    assert deps == {"https://cli.github.com/packages"}


def test_apt_sources_list_write_extracts_repo_url_from_sudo_shell_echo():
    findings = scan(
        "sudo sh -c 'echo \"deb http://packages.ros.org/ros/ubuntu $(lsb_release -sc) main\" "
        "> /etc/apt/sources.list.d/ros-latest.list'\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "apt-sources-list-write"
    }
    assert deps == {"http://packages.ros.org/ros/ubuntu"}


def test_apt_sources_list_write_extracts_repo_url_before_tee_destination():
    findings = scan(
        'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] '
        'https://baltocdn.com/helm/stable/debian/ all main" '
        '| sudo tee /etc/apt/sources.list.d/helm-stable-debian.list\n',
        "ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "apt-sources-list-write"
    }
    assert deps == {"https://baltocdn.com/helm/stable/debian/"}


def test_apt_sources_list_write_extracts_repo_url_from_split_echo_context():
    findings = scan(
        'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] '
        'https://download.docker.com/linux/ubuntu \\\n'
        '  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null\n',
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "apt-sources-list-write"
    }
    assert deps == {"https://download.docker.com/linux/ubuntu"}


def test_apt_sources_list_write_keeps_shell_substitution_inside_repo_url():
    url = "https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]')"
    findings = scan(
        f'echo "deb [arch=amd64] {url} $(lsb_release -cs) stable" '
        "| tee /etc/apt/sources.list.d/docker.list\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "apt-sources-list-write"
    }
    assert deps == {url}


def test_apt_sources_list_write_extracts_repo_url_from_sources_heredoc():
    findings = scan(
        "sudo tee /etc/apt/sources.list.d/docker.sources <<EOF\n"
        "Types: deb\n"
        "URIs: https://download.docker.com/linux/ubuntu\n"
        "Suites: $(. /etc/os-release && echo \"${UBUNTU_CODENAME:-$VERSION_CODENAME}\")\n"
        "Components: stable\n"
        "EOF\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "apt-sources-list-write"
    }
    assert deps == {"https://download.docker.com/linux/ubuntu"}


def test_winget_install_ignores_custom_powershell_write_helper():
    findings = scan(
        "Write-Warn2 '        winget install --id Python.Python.3.12 --architecture x64'\n",
        "script",
        "Install-EssAdk.ps1",
    )

    assert not any(f.pattern_id == "winget-command-install" for f in findings)


def test_winget_install_ignores_powershell_block_comment_prereqs():
    findings = scan(
        "<#\n"
        "1. PowerShell 7+ (winget install Microsoft.PowerShell)\n"
        "2. Python 3.12+ (winget install Python.Python.3.12)\n"
        "#>\n"
        "winget install --id Git.Git --source winget\n",
        "script",
        "prereqs-windows.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "winget-command-install"
    }
    assert deps == {"Git.Git"}


def test_winget_install_resolves_wrapper_call_literal_ids():
    findings = scan(
        "function Install-WithWinget {\n"
        "    param([string]$Id, [string]$Reason = $Id)\n"
        "    & winget install --id $Id --silent --accept-package-agreements\n"
        "}\n"
        "Install-WithWinget -Id 'Microsoft.DotNet.SDK.10' -Reason '.NET SDK'\n"
        "& winget install --id Microsoft.WinAppCli --silent\n",
        "script",
        "bootstrap.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "winget-command-install"
    }
    assert deps == {"Microsoft.DotNet.SDK.10", "Microsoft.WinAppCli"}


def test_winget_install_resolves_assigned_package_id_variable():
    findings = scan(
        '$rubyPackageName = "RubyInstallerTeam.RubyWithDevKit.3.1";\n'
        "winget install --id $rubyPackageName --source winget --accept-source-agreements\n",
        "script",
        "install.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "winget-command-install"
    }
    assert deps == {"RubyInstallerTeam.RubyWithDevKit.3.1"}


def test_winget_install_resolves_foreach_hashtable_id_property():
    findings = scan(
        "$packages = @(\n"
        "    @{ Id = 'Python.Python.3.12'; Name = 'Python 3.12'; Cmd = 'python' },\n"
        "    @{ Id = 'Git.Git'; Name = 'Git for Windows'; Cmd = 'git' }\n"
        ")\n"
        "foreach ($pkg in $packages) {\n"
        "    & winget install --id $pkg.Id --source winget --exact --silent\n"
        "}\n",
        "script",
        "Install-EssAdk.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "winget-command-install"
    }
    assert deps == {"Python.Python.3.12", "Git.Git"}


def test_winget_install_ignores_unresolved_package_id_variable():
    findings = scan(
        "function Install-WithWinget {\n"
        "    param($PackageId, $PackageName)\n"
        "    winget install --id $PackageId --accept-source-agreements --accept-package-agreements\n"
        "}\n",
        "script",
        "setup.ps1",
    )

    assert not any(
        f.pattern_id == "winget-command-install"
        and f.extracted_dep == "$PackageId"
        for f in findings
    )


def test_system_package_install_keeps_github_expression_package_template():
    findings = scan(
        "apt-get install -y postgresql-${{ matrix.pg_version }} postgresql-server-dev-${{ matrix.pg_version }}\n",
        "ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "system-package-install"
    }
    assert deps == {
        "postgresql-${{matrix.pg_version}}",
        "postgresql-server-dev-${{matrix.pg_version}}",
    }


def test_system_package_install_stops_before_markdown_parenthetical():
    findings = scan(
        "- sudo apt install gh (Debian/Ubuntu — see https://cli.github.com for other distros)\n",
        "agent_instruction",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "system-package-install"
    }
    assert deps == {"gh"}


def test_system_package_install_detects_zypper_global_options():
    findings = scan(
        "sudo zypper --non-interactive install -y make automake libtool\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "system-package-install"
    }
    assert {"make", "automake", "libtool"} <= deps


def test_system_package_install_detects_python_subprocess_shell_command():
    findings = scan(
        "import subprocess\n"
        "subprocess.run('sudo apt-get install make automake libtool -y --quiet', shell=True, check=True)\n",
        "source_code",
        "configure.py",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "system-package-install"
    }
    assert {"make", "automake", "libtool"} <= deps


def test_system_package_install_ignores_non_shell_python_subprocess_string():
    findings = scan(
        "import subprocess\n"
        "subprocess.run('sudo apt-get install make automake libtool', check=True)\n",
        "source_code",
        "configure.py",
    )

    assert not any(f.pattern_id == "system-package-install" for f in findings)


def test_ignores_routine_dockerfile_system_packages():
    findings = scan("RUN apk add --no-cache ca-certificates\n", "dockerfile")

    assert not any(f.pattern_id == "system-package-install" for f in findings)


def test_ignores_ci_metadata_labels_that_mention_install_commands():
    findings = scan(
        "displayName: npm install validation (win-x64)\n"
        "name: pip install asciinema\n"
        "- name: pip install asciinema\n",
        "ci",
        "azure-pipelines.yml",
    )

    assert findings == []


def test_cargo_install_reports_each_package():
    findings = scan(
        "cargo install cargo-llvm-cov cargo-nextest maturin --locked\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "cargo-install"
    }
    assert {"cargo-llvm-cov", "cargo-nextest", "maturin"} <= deps


def test_cargo_install_allows_toolchain_prefix():
    findings = scan("cargo +nightly install cargo-fuzz\n", "script")

    assert any(
        f.pattern_id == "cargo-install" and f.extracted_dep == "cargo-fuzz"
        for f in findings
    )


def test_cargo_install_reports_inline_version_specs():
    findings = scan(
        "RUN cargo install cargo-chef@${CARGO_CHEF_VERSION} --locked\n"
        "RUN cargo install cargo-binstall@1.6.6\n",
        "dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "cargo-install"
    }
    assert deps == {"cargo-chef@${CARGO_CHEF_VERSION}", "cargo-binstall@1.6.6"}


def test_cargo_install_reports_git_source_with_revision():
    findings = scan(
        'install_script = "set RUSTFLAGS= && cargo install --git '
        'https://github.com/tamasfe/taplo --rev b673b44d taplo-cli --locked --force"\n',
        "build",
        "Makefile.toml",
    )

    assert any(
        f.pattern_id == "cargo-install" and f.extracted_dep == "taplo-cli"
        for f in findings
    )
    assert any(
        f.pattern_id == "cargo-install-git-source"
        and f.extracted_dep == "https://github.com/tamasfe/taplo#rev=b673b44d"
        for f in findings
    )


def test_cargo_install_reports_git_source_equals_branch_syntax():
    findings = scan(
        "cargo +nightly install --git=https://github.com/example/tool "
        "--branch main tool-cli --locked\n",
        "ci",
    )

    assert any(
        f.pattern_id == "cargo-install-git-source"
        and f.extracted_dep == "https://github.com/example/tool#branch=main"
        for f in findings
    )


def test_cargo_install_ignores_unresolved_git_source():
    findings = scan("cargo install --git $TAPLO_REPO taplo-cli --locked\n", "ci")

    assert not any(f.pattern_id == "cargo-install-git-source" for f in findings)
    assert any(
        f.pattern_id == "cargo-install" and f.extracted_dep == "taplo-cli"
        for f in findings
    )


def test_cargo_install_ignores_unresolved_variable_crate_name():
    findings = scan("cargo install --locked $toolName --version $version\n", "github_action")

    assert not any(f.pattern_id == "cargo-install" for f in findings)


def test_cargo_install_ignores_local_path_install():
    findings = scan("cargo install --path agentmesh --features cli\n", "agent_instruction")

    assert not any(f.pattern_id == "cargo-install" for f in findings)


def test_cargo_install_ignores_inline_hash_comment_words():
    findings = scan("cargo install cargo-fuzz            # Install cargo-fuzz\n", "ci")

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "cargo-install"
    }
    assert deps == {"cargo-fuzz"}


def test_cargo_binstall_detects_prebuilt_binary_install_and_dedupes_fallback():
    findings = scan(
        "cargo binstall --no-confirm --locked just || cargo install --locked just\n",
        "github_action",
    )

    assert any(
        f.pattern_id == "cargo-binstall" and f.extracted_dep == "just"
        for f in findings
    )
    assert not any(
        f.pattern_id == "cargo-install" and f.extracted_dep == "just"
        for f in findings
    )


def test_cargo_binstall_reports_each_package():
    findings = scan(
        "cargo +nightly binstall cargo-nextest cargo-llvm-cov --version 1.2.3 --locked\n",
        "ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "cargo-binstall"
    }
    assert {"cargo-nextest", "cargo-llvm-cov"} <= deps


def test_rustup_target_add_detects_literal_targets():
    findings = scan(
        "run: rustup target add wasm32-unknown-unknown\n"
        "rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc >nul 2>&1\n",
        "ci",
        ".github/workflows/ci.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "rustup-target-add"
    }
    assert deps == {
        "wasm32-unknown-unknown",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    }


def test_rustup_target_add_skips_toolchain_flag_and_dynamic_values():
    findings = scan(
        "rustup target add --toolchain 1.86.0-x86_64-unknown-linux-gnu x86_64-linux-android\n"
        'rustup target add "$RUST_TARGET"\n'
        "rustup target add %BUILD_ARCH%\n",
        "script",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "rustup-target-add"
    ]
    assert deps == ["x86_64-linux-android"]


def test_rustup_add_skips_github_expression_values():
    findings = scan(
        "rustup target add ${{ matrix.target }}\n"
        "rustup component add ${{ inputs.components }}\n",
        "github_action",
    )

    assert not any(
        f.pattern_id in {"rustup-target-add", "rustup-component-add"}
        for f in findings
    )


def test_rustup_component_add_detects_literal_components():
    findings = scan(
        "run: rustup show && rustup component add rustfmt clippy\n"
        "rustup component add llvm-tools-preview --toolchain stable\n",
        "ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "rustup-component-add"
    }
    assert deps == {"rustfmt", "clippy", "llvm-tools-preview"}


def test_rustup_component_add_ignores_comments_and_printed_guidance():
    findings = scan(
        "# rustup component add clippy\n"
        'throw "Run: rustup component add llvm-tools-preview --toolchain stable"\n'
        'echo "rustup component add rustfmt"\n'
        "rustup component add rust-src\n",
        "script",
        "Generate-Coverage.ps1",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "rustup-component-add"
    ]
    assert deps == ["rust-src"]


def test_rustup_add_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `rustup target add wasm32-unknown-unknown` for WASM examples.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(
        f.pattern_id in {"rustup-target-add", "rustup-component-add"}
        for f in findings
    )


def test_rustup_toolchain_install_detects_literal_toolchains():
    findings = scan(
        "run: rustup toolchain install nightly --component miri\n"
        "rustup install 1.86.0\n"
        "rustup toolchain install stable-x86_64-pc-windows-msvc --profile minimal\n",
        "ci",
        ".github/workflows/ci.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "rustup-toolchain-install"
    }
    assert deps == {"nightly", "1.86.0", "stable-x86_64-pc-windows-msvc"}


def test_rustup_toolchain_update_and_default_detect_chained_commands():
    findings = scan(
        "rustup update --no-self-update stable && rustup default stable\n"
        "rustup update nightly && rustup default nightly-x86_64-pc-windows-msvc\n",
        "ci",
    )

    updates = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "rustup-toolchain-update"
    }
    defaults = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "rustup-toolchain-default"
    }
    assert updates == {"stable", "nightly"}
    assert defaults == {"stable", "nightly-x86_64-pc-windows-msvc"}


def test_rustup_toolchain_default_keeps_literal_channel_with_github_expression_suffix():
    findings = scan(
        "rustup default stable-${{ matrix.host }}\n"
        "rustup update ${{ matrix.toolchain }}\n",
        "github_action",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "rustup-toolchain-default"
    }
    assert deps == {"stable-${{ matrix.host }}"}
    assert not any(f.extracted_dep == "${{ matrix.toolchain }}" for f in findings)


def test_rustup_toolchain_install_skips_dynamic_values_and_guidance():
    findings = scan(
        "rustup toolchain install ${RUST_CHANNEL} --profile minimal\n"
        "rustup default $rustVersion\n"
        "rustup toolchain install $(awk -F'\\\"' '/channel/{print $2}' rust-toolchain.toml)\n"
        'echo "rustup toolchain install nightly"\n'
        "# rustup update stable\n"
        "rustup toolchain install beta\n",
        "script",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id.startswith("rustup-toolchain-")
    ]
    assert deps == ["beta"]


def test_rustup_toolchain_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `rustup toolchain install nightly` before fuzzing.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id.startswith("rustup-toolchain-") for f in findings)


def test_version_manager_installs_detect_pyenv_and_tfenv_versions():
    findings = scan(
        "pyenv install 3.13:latest 3.12:latest 3.9:latest\n"
        "pyenv install 3.12.10 -f\n"
        "pyenv install $pythonVersion\n"
        "tfenv install latest\n",
        "script",
        "setup.sh",
    )

    pyenv_deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pyenv-install"
    }
    tfenv_deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "tfenv-install"
    }
    assert pyenv_deps == {
        "3.13:latest",
        "3.12:latest",
        "3.9:latest",
        "3.12.10",
        "$pythonVersion",
    }
    assert tfenv_deps == {"latest"}


def test_version_manager_installs_detect_nvm_and_fnm_versions():
    findings = scan(
        'RUN su $USERNAME -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && '
        'nvm install ${NODE_VERSION} 2>&1"\n'
        "fnm install 20 && npm ci\n",
        "dockerfile",
        ".devcontainer/Dockerfile",
    )

    deps_by_pattern = {
        f.pattern_id: f.extracted_dep
        for f in findings
        if f.pattern_id in {"nvm-install", "fnm-install"}
    }
    assert deps_by_pattern == {
        "nvm-install": "${NODE_VERSION}",
        "fnm-install": "20",
    }


def test_version_manager_installs_ignore_list_guidance_and_inert_strings():
    findings = scan(
        "pyenv install --list\n"
        'echo "pyenv install 3.12.10"\n'
        'cmd="tfenv install latest"\n'
        'msg="nvm install 20"\n'
        'echo "fnm install 20"\n'
        "tfenv install 1.9.8\n",
        "script",
        "setup.sh",
    )

    deps_by_pattern = {
        f.pattern_id: f.extracted_dep
        for f in findings
        if f.pattern_id in {"pyenv-install", "tfenv-install"}
    }
    assert deps_by_pattern == {"tfenv-install": "1.9.8"}


def test_version_manager_installs_ignore_non_control_markdown_examples():
    findings = scan(
        "# Setup\n\nRun `pyenv install 3.12.10` before testing Terraform with `tfenv install latest`.\n"
        "Use `nvm install <ver>` or `fnm install 20` for local Node.js setup.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(
        f.pattern_id in {"pyenv-install", "tfenv-install", "nvm-install", "fnm-install"}
        for f in findings
    )


def test_brew_tap_detects_non_default_homebrew_source():
    findings = scan(
        "brew tap wix/brew\n"
        "brew install applesimutils\n",
        "ci",
    )

    assert any(
        f.pattern_id == "brew-tap-ci"
        and f.extracted_dep == "wix/brew"
        for f in findings
    )
    assert any(
        f.pattern_id == "brew-install-ci"
        and f.extracted_dep == "applesimutils"
        for f in findings
    )


def test_brew_tap_detects_url_tap_source():
    findings = scan("brew tap org/tools https://github.com/org/homebrew-tools\n", "script")

    assert any(
        f.pattern_id == "brew-tap-ci"
        and f.extracted_dep == "org/tools"
        for f in findings
    )


def test_brew_tap_ignores_printed_install_guidance():
    findings = scan(
        'echo "Install with: brew tap wix/brew && brew install applesimutils"\n'
        "brew tap azure/azd && brew install azd\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "brew-tap-ci"
    }
    assert deps == {"azure/azd"}


def test_go_install_ignores_local_package_with_make_flags():
    findings = scan("go install $(LDFLAGS) ./cmd/waza\n", "build")

    assert not any(f.pattern_id == "go-install" for f in findings)


def test_go_install_keeps_external_module_after_flags():
    findings = scan(
        'go install -ldflags "$LDFLAGS" github.com/example/tool/cmd/tool@latest\n',
        "script",
    )

    assert any(
        f.pattern_id == "go-install"
        and f.extracted_dep == "github.com/example/tool/cmd/tool@latest"
        for f in findings
    )


def test_go_run_remote_detects_versioned_module_execution():
    findings = scan(
        "@!(go run golang.org/x/tools/cmd/goimports@latest -l -d ${GOFILES} | grep '[a-z]')\n",
        "build",
    )

    assert any(
        f.pattern_id == "go-run-remote"
        and f.extracted_dep == "golang.org/x/tools/cmd/goimports@latest"
        and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_go_run_remote_skips_local_runs_comments_and_guidance():
    findings = scan(
        "# go run golang.org/x/tools/cmd/goimports@latest\n"
        'echo "go run golang.org/x/tools/cmd/goimports@latest"\n'
        "go run ./cmd/tool\n"
        "go run github.com/example/tool/cmd/tool\n"
        "go run github.com/example/tool/cmd/tool@v1.2.3\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "go-run-remote"
    }
    assert deps == {"github.com/example/tool/cmd/tool@v1.2.3"}


def test_go_run_remote_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `go run golang.org/x/tools/cmd/goimports@latest` before linting.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "go-run-remote" for f in findings)


def test_go_install_keeps_external_module_with_shell_version_substitution():
    findings = scan(
        'go install "github.com/microsoft/azure-linux-dev-tools/cmd/azldev@$(cat .azldev-version)"\n'
        'go install "github.com/microsoft/azure-linux-dev-tools/cmd/azldev@${AZLDEV_VERSION}"\n',
        "ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "go-install"
    }
    assert deps == {
        "github.com/microsoft/azure-linux-dev-tools/cmd/azldev@$(cat .azldev-version)",
        "github.com/microsoft/azure-linux-dev-tools/cmd/azldev@${AZLDEV_VERSION}",
    }


def test_go_install_keeps_external_module_with_github_expression_version():
    findings = scan(
        "run: go install gotest.tools/gotestsum@${{ env.GOTESTSUM_VERSION }}\n",
        "ci",
    )

    assert any(
        f.pattern_id == "go-install"
        and f.extracted_dep == "gotest.tools/gotestsum@${{ env.GOTESTSUM_VERSION }}"
        for f in findings
    )


def test_go_install_reads_dockerfile_line_continuation_module():
    findings = scan(
        'RUN test -n "${AZLDEV_VERSION}" \\\n'
        '    && GOBIN=/usr/local/bin go install \\\n'
        '    "github.com/microsoft/azure-linux-dev-tools/cmd/azldev@${AZLDEV_VERSION}" \\\n'
        "    && rm -rf /root/go /root/.cache\n",
        "dockerfile",
    )

    assert any(
        f.pattern_id == "go-install"
        and f.extracted_dep == "github.com/microsoft/azure-linux-dev-tools/cmd/azldev@${AZLDEV_VERSION}"
        for f in findings
    )


def test_go_install_ignores_dynamic_only_module_with_flags():
    findings = scan('go install -tags caphtools "${1}@${3}"\n', "script")

    assert not any(f.pattern_id == "go-install" for f in findings)


def test_detects_go_generate_directive_at_line_start():
    findings = scan("//go:generate go tool stringer -type=Kind\n", "source_code", "kind.go")

    assert any(
        f.pattern_id == "go-generate-command"
        and f.extracted_dep == "go"
        for f in findings
    )


def test_go_generate_command_ignores_string_literal():
    findings = scan(
        'w.write("//go:generate npx dprint fmt kind_stringer_generated.go");\n',
        "source_code",
        "generate-go-ast.ts",
    )

    assert not any(f.pattern_id == "go-generate-command" for f in findings)


def test_brew_install_skips_cask_flag_before_package():
    findings = scan("brew install --cask microsoft/aspire/aspire\n", "ci")

    assert any(
        f.pattern_id == "brew-install-ci"
        and f.extracted_dep == "microsoft/aspire/aspire"
        for f in findings
    )
    assert not any(
        f.pattern_id == "brew-install-ci" and f.extracted_dep == "--cask"
        for f in findings
    )


def test_brew_install_keeps_quoted_variable_package_after_cask_flag():
    findings = scan('brew install --cask "$cask" || true\n', "script")

    assert any(
        f.pattern_id == "brew-install-ci"
        and f.extracted_dep == "$cask"
        for f in findings
    )
    assert not any(
        f.pattern_id == "brew-install-ci" and f.extracted_dep == "--cask"
        for f in findings
    )


def test_brew_install_skips_no_sandbox_flag_before_package():
    findings = scan("yes | ACCEPT_EULA=Y brew install --no-sandbox msodbcsql >> env_setup.log\n", "script")

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "brew-install-ci"
    }
    assert "msodbcsql" in deps
    assert "--no-sandbox" not in deps


def test_brew_install_reports_each_package_and_skips_redirection():
    findings = scan("brew install autoconf automake libtool >> env_setup.log\n", "script")

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "brew-install-ci"
    }
    assert {"autoconf", "automake", "libtool"} <= deps
    assert "env_setup.log" not in deps


def test_brew_install_ignores_echoed_install_hint_in_makefile():
    findings = scan(
        '@command -v "$(XCODEGEN)" >/dev/null || { echo "error: xcodegen not found. '
        'Install it with \'brew install xcodegen\' or run \'make dev-setup\'."; exit 1; }\n',
        "build",
        "Makefile",
    )

    assert not any(f.pattern_id == "brew-install-ci" for f in findings)


def test_brew_install_ignores_missing_items_help_array():
    findings = scan(
        'missing_items+=("swiftlint (brew install swiftlint)")\n'
        "brew install azure-cli\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "brew-install-ci"
    }
    assert deps == {"azure-cli"}


def test_ignores_js_issue_comment_install_hints():
    findings = scan(
        'let body = "Please install `autoconf-archive` via `brew install autoconf-archive` '
        '(macos) or `sudo apt-get install autoconf-archive` (linux)"\n',
        "ci",
        "check_issues.yml",
    )

    assert not any(
        f.pattern_id in {"brew-install-ci", "system-package-install"}
        for f in findings
    )


def test_pip_install_ci_ignores_printed_status_about_pip_install_packages():
    findings = scan(
        "print(f'OK: All notebook pip install packages are registered')\n",
        "ci",
        "workflow.yml",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_plain_prose_about_pip_install_command():
    findings = scan(
        "**Hardcoded package name:** The pip install command uses the literal string `agent-failsafe[server]`.\n"
        "| pip install runs with user privileges | Low | Standard pip behavior. |\n",
        "agent_instruction",
        "SECURITY.md",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_parenthetical_prose_with_plus_separator():
    findings = scan(
        "step1.md (pip install + server start). Then retry the failed call.\n",
        "agent_instruction",
        "step2.md",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_pip_install_ci_ignores_markdown_table_failure_prose():
    findings = scan(
        '| Deployment hangs in "Building..." | Oryx pip install failing on native deps | '
        'Run `az webapp log deployment list -n <app> -g <rg>` |\n',
        "agent_instruction",
        "errors.md",
    )

    assert not any(f.pattern_id == "pip-install-ci" for f in findings)


def test_gem_install_detects_multiple_gems_and_skips_options():
    findings = scan(
        "gem install jekyll bundler\n"
        "sudo gem install jazzy --version 0.14.3\n"
        "gem install --source https://rubygems.org --install-dir vendor/bundle fpm --no-document\n",
        "build",
        "Makefile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "gem-install"
    }
    assert deps == {"jekyll", "bundler", "jazzy", "fpm"}


def test_gem_install_ignores_guidance_and_prose():
    findings = scan(
        'echo "gem install bundler"\n'
        "Never `gem install` outside Bundler; use the Gemfile instead.\n"
        "gem install cddl\n",
        "agent_instruction",
        "AGENTS.md",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "gem-install"
    ]
    assert deps == ["cddl"]


def test_dotnet_tool_install_skips_local_flag_before_package():
    findings = scan("dotnet tool install --local Hex1b.Tool\n", "agent_instruction")

    assert any(
        f.pattern_id == "dotnet-tool-install"
        and f.extracted_dep == "Hex1b.Tool"
        for f in findings
    )
    assert not any(
        f.pattern_id == "dotnet-tool-install" and f.extracted_dep == "--local"
        for f in findings
    )


def test_dotnet_tool_install_detects_folded_yaml_package_line():
    findings = scan(
        "run: >\n"
        "  dotnet tool install\n"
        "  Azure.Sdk.Tools.GitHubEventProcessor\n"
        "  --version 1.0.0-dev.20260403.1\n"
        "  --add-source https://pkgs.dev.azure.com/azure-sdk/public/_packaging/azure-sdk-for-net/nuget/v3/index.json\n"
        "  --global\n",
        "ci",
        ".github/workflows/event-processor.yml",
    )

    assert any(
        f.pattern_id == "dotnet-tool-install"
        and f.extracted_dep == "Azure.Sdk.Tools.GitHubEventProcessor"
        and f.line_number == 2
        for f in findings
    )


def test_dotnet_tool_install_ignores_unresolved_environment_package_variable():
    findings = scan(
        "dotnet tool install -g $env:BCAL_PACKAGE_ID "
        "--prerelease --add-source $env:BCAL_FEED_URL\n",
        "ci",
        ".github/workflows/bcal-evaluation.yml",
    )

    assert not any(
        f.pattern_id == "dotnet-tool-install"
        and f.extracted_dep == "$env:BCAL_PACKAGE_ID"
        for f in findings
    )


def test_dotnet_tool_install_ignores_install_update_failure_message():
    findings = scan(
        "if ($LASTEXITCODE -ne 0) { "
        "Fail '`dotnet tool install/update` failed for Microsoft.UI.Reactor.Cli' }\n",
        "script",
        "bootstrap.ps1",
    )

    assert not any(f.pattern_id == "dotnet-tool-install" for f in findings)


def test_dotnet_workload_detects_update_restore_and_literal_install():
    findings = scan(
        "sudo dotnet workload update\n"
        "run: dotnet workload restore EventLogExpert.slnx\n"
        "dotnet workload install wasm-tools maui --source https://api.nuget.org/v3/index.json\n",
        "ci",
    )

    by_pattern = {
        (f.pattern_id, f.extracted_dep)
        for f in findings
        if f.pattern_id.startswith("dotnet-workload-")
    }
    assert ("dotnet-workload-update", "update") in by_pattern
    assert ("dotnet-workload-restore", "restore") in by_pattern
    assert ("dotnet-workload-install", "wasm-tools") in by_pattern
    assert ("dotnet-workload-install", "maui") in by_pattern


def test_dotnet_workload_detects_devcontainer_command_string():
    findings = scan(
        '{"onCreateCommand": "sudo ./dotnet-install.sh --install-dir /usr/lib/dotnet '
        '&& sudo dotnet workload update && dotnet tool install --global PowerShell"}\n',
        "devcontainer",
        "devcontainer.json",
    )

    assert any(
        f.pattern_id == "dotnet-workload-update"
        and f.extracted_dep == "update"
        for f in findings
    )


def test_devcontainer_detects_lifecycle_tool_installs():
    findings = scan(
        "{\n"
        '  "postCreateCommand": {\n'
        '    "node": "npm install -g hereby; npm ci",\n'
        '    "node-update": "npm install npm --global && npm ci",\n'
        '    "go": "go install github.com/google/pprof@latest",\n'
        '    "uv": "uv tool install pre-commit --with pre-commit-uv --force-reinstall"\n'
        "  }\n"
        "}\n",
        "devcontainer",
        "devcontainer.json",
    )

    by_pattern = {
        (f.pattern_id, f.extracted_dep)
        for f in findings
    }
    assert ("npm-global-install", "hereby") in by_pattern
    assert ("npm-global-install-flag-after", "npm") in by_pattern
    assert ("go-install", "github.com/google/pprof@latest") in by_pattern
    assert ("uv-tool-install", "pre-commit") in by_pattern


def test_devcontainer_ignores_requirements_file_pip_install():
    findings = scan(
        '{"postCreateCommand": "pip install -r requirements.txt && uv pip install -r pylock.toml"}\n',
        "devcontainer",
        "devcontainer.json",
    )

    assert not any(
        f.pattern_id in {"pip-install-ci", "uv-pip-install"}
        for f in findings
    )


def test_dotnet_workload_ignores_comments_errors_and_dynamic_install_list():
    findings = scan(
        "# dotnet workload update\n"
        "Write-PipelineTelemetryError -Category 'InitializeToolset' "
        "\"Failed to install workloads '${missing[*]}' (dotnet workload install exit code $LASTEXITCODE).\"\n"
        "& $dotnet workload install @missing\n"
        "dotnet workload install android\n",
        "script",
        "restore-toolset.ps1",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "dotnet-workload-install"
    ]
    assert deps == ["android"]


def test_dotnet_workload_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `dotnet workload update` before building mobile samples.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id.startswith("dotnet-workload-") for f in findings)


def test_ignores_batch_comment_install_commands():
    findings = scan(
        "REM     $:\\> dotnet tool install --global coverlet.console --version 3.2.0\n"
        "REM pip install airsim --upgrade\n"
        ":: npm install -g pnpm\n"
        ":: pip3 install yolk3k\n"
        "dotnet tool install --global real.tool\n",
        "script",
        "coverage.cmd",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id in {"dotnet-tool-install", "npm-global-install", "pip-install-ci"}
    }
    assert deps == {"real.tool"}


def test_detects_windows_nuget_and_dotnet_package_manager_installs():
    findings = scan(
        "& winget install --id Microsoft.WinAppCli --silent\n"
        "winget install Microsoft.DotNet.SDK.10\n"
        "choco install git -y\n"
        "scoop install main/ripgrep\n"
        "dotnet tool update -g --add-source $feed Microsoft.UI.Reactor.Cli --no-cache\n"
        "dotnet new install $templateNupkg\n"
        "nuget install Microsoft.CodeAnalysis.BinSkim -Version 4.4.9.9\n",
        "script",
        "bootstrap.ps1",
    )

    by_pattern = {(f.pattern_id, f.extracted_dep) for f in findings}
    assert ("winget-command-install", "Microsoft.WinAppCli") in by_pattern
    assert ("winget-command-install", "Microsoft.DotNet.SDK.10") in by_pattern
    assert ("choco-install", "git") in by_pattern
    assert ("scoop-install", "main/ripgrep") in by_pattern
    assert ("dotnet-tool-install", "Microsoft.UI.Reactor.Cli") in by_pattern
    assert ("dotnet-template-install", "$templateNupkg") in by_pattern
    assert ("nuget-install", "Microsoft.CodeAnalysis.BinSkim") in by_pattern


def test_nuget_install_resolves_powershell_foreach_string_array():
    findings = scan(
        '$packagesToInstall = @("Microsoft.Windows.WDK.x64", "Microsoft.Windows.WDK.ARM64")\n'
        "foreach ($packageName in $packagesToInstall) {\n"
        "    nuget install $packageName -Version $version -OutputDirectory $packagesRootDir\n"
        "}\n",
        "github_action",
        "action.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "nuget-install"
    }
    assert deps == {"Microsoft.Windows.WDK.x64", "Microsoft.Windows.WDK.ARM64"}


def test_nuget_install_resolves_multiline_powershell_string_array():
    findings = scan(
        "$packagesToInstall = @(\n"
        '    "Microsoft.Windows.WDK.x64",\n'
        '    "Microsoft.Windows.WDK.ARM64"\n'
        ")\n"
        "foreach ($packageName in $packagesToInstall) {\n"
        "    & $NuGetExe install $packageName `\n"
        "        -Version $version `\n"
        "        -OutputDirectory $packagesRootDir\n"
        "}\n",
        "script",
        "install-wdk.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "nuget-install"
    }
    assert deps == {"Microsoft.Windows.WDK.x64", "Microsoft.Windows.WDK.ARM64"}


def test_nuget_install_ignores_unresolved_environment_package_variable():
    findings = scan(
        "nuget install $env:ORT_PACKAGE_NAME -version $env:ORT_TEST_VERSION "
        "-Source $env:ORT_NIGHTLY_FEED -NonInteractive\n",
        "ci",
        ".github/workflows/build.yml",
    )

    assert not any(f.pattern_id == "nuget-install" for f in findings)


def test_detects_azure_cli_extension_install_variants():
    findings = scan(
        "az extension add --name application-insights --only-show-errors >/dev/null 2>&1 || true\n"
        "az extension add -n containerapp --upgrade\n"
        "Invoke-Az extension add --name azure-devops --yes | Out-Null\n",
        "script",
        "bootstrap.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "azure-cli-extension-install"
    }
    assert deps == {"application-insights", "containerapp", "azure-devops"}


def test_detects_azure_cli_managed_tool_installs():
    findings = scan(
        "- name: Install Bicep CLI\n"
        "  run: az bicep install\n"
        "- run: az bicep upgrade\n"
        "- run: az aks install-cli --install-location ./kubectl "
        "--kubelogin-install-location ./kubelogin\n",
        "ci",
        ".github/workflows/deploy.yml",
    )

    by_pattern = {(f.pattern_id, f.extracted_dep) for f in findings}
    assert ("azure-cli-bicep-install", "bicep") in by_pattern
    assert ("azure-cli-aks-install-cli", "aks install-cli") in by_pattern


def test_azure_cli_managed_tool_installs_ignore_printed_guidance():
    findings = scan(
        "# az bicep install\n"
        'echo "az aks install-cli"\n'
        "az bicep install\n",
        "script",
        "bootstrap.sh",
    )

    by_pattern = [
        (f.pattern_id, f.extracted_dep)
        for f in findings
        if f.pattern_id.startswith("azure-cli-")
    ]
    assert by_pattern == [("azure-cli-bicep-install", "bicep")]


def test_azure_cli_managed_tool_installs_ignore_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `az bicep install` and `az aks install-cli` before deploying.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(
        f.pattern_id in {"azure-cli-bicep-install", "azure-cli-aks-install-cli"}
        for f in findings
    )


def test_detects_azure_cli_extension_install_in_python_shell_call():
    content = 'import os\nos.system("az extension add --name acrtransfer")\n'
    scanner = UnmanagedPackageScanner(Config())
    target = FileTarget(
        path=Path("/tmp/clean_acr.py"),
        rel_path="clean_acr.py",
        file_type="source_code",
    )
    findings = scanner.scan_file_content(target, content, content.splitlines())

    assert any(
        f.pattern_id == "azure-cli-extension-install"
        and f.extracted_dep == "acrtransfer"
        for f in findings
    )


def test_detects_azure_cli_extension_install_in_typescript_execsync_shell_call():
    findings = scan(
        "import { execSync } from 'child_process';\n"
        "execSync('az extension show --name azure-devops', { stdio: 'ignore' });\n"
        "console.log('Then add the DevOps extension: az extension add --name azure-devops');\n"
        "execSync('az extension add --name azure-devops', { stdio: 'inherit' });\n",
        "source_code",
        ".github/skills/azure-pipelines/azure-pipeline.ts",
    )

    rows = [
        (f.line_number, f.extracted_dep)
        for f in findings
        if f.pattern_id == "azure-cli-extension-install"
    ]
    assert rows == [(4, "azure-devops")]


def test_detects_azure_cli_extension_install_from_shell_wrapper_call():
    findings = scan(
        'install_admin_azure_cli_extension() {\n'
        '  local extension_name="$1"\n'
        '  sudo -H -u "$ADMIN_USER" bash -lc "az extension add --name \'${extension_name}\' --yes"\n'
        '}\n'
        'install_admin_azure_cli_extension "ml"\n',
        "script",
        "install-dev-deps.sh",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "azure-cli-extension-install"
    }
    assert deps == {"ml"}


def test_detects_azure_cli_extension_install_from_powershell_psitem_pipeline():
    findings = scan(
        "@('ssh', 'log-analytics-solution', 'connectedmachine', 'monitor-control-service') |\n"
        "ForEach-Object -Parallel {\n"
        "    az extension add --name $PSItem --yes --only-show-errors\n"
        "}\n",
        "script",
        "MHServersLogonScript.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "azure-cli-extension-install"
    }
    assert deps == {"ssh", "log-analytics-solution", "connectedmachine", "monitor-control-service"}


def test_azure_cli_extension_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `az extension add --name containerapp --upgrade` before the lab.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(
        f.pattern_id == "azure-cli-extension-install"
        for f in findings
    )


def test_detects_github_cli_extension_install_variants():
    findings = scan(
        "run: gh extension install github/gh-aw\n"
        "gh extension install Evangelink/gh-copilot-curate --pin v0.6.0\n"
        "gh extension install --pin v0.6.0 owner/gh-tool\n"
        "gh extension upgrade github/gh-aw\n",
        "ci",
        ".github/workflows/copilot.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "github-cli-extension-install"
    }
    assert deps == {"github/gh-aw", "Evangelink/gh-copilot-curate", "owner/gh-tool"}


def test_github_cli_extension_ignores_comments_and_printed_guidance():
    findings = scan(
        "#   gh extension install microsoft/gh-agent-os\n"
        'echo "gh extension install github/gh-aw"\n'
        "gh extension install github/gh-real\n",
        "script",
        "setup.sh",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "github-cli-extension-install"
    ]
    assert deps == ["github/gh-real"]


def test_github_cli_extension_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `gh extension install github/gh-aw` if you want the optional tool.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(
        f.pattern_id == "github-cli-extension-install"
        for f in findings
    )


def test_detects_vscode_extension_install_variants():
    findings = scan(
        "code --install-extension ms-python.python                # Python\n"
        "code --install-extension ms-vscode-remote.remote-wsl --force 2>/dev/null || true\n"
        "if code --install-extension GitHub.copilot-chat --force > /dev/null 2>&1; then\n",
        "script",
        "bootstrap-dev-env.sh",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "vscode-extension-install"
    }
    assert deps == {
        "ms-python.python",
        "ms-vscode-remote.remote-wsl",
        "GitHub.copilot-chat",
    }


def test_detects_vscode_extension_installs_from_extension_arrays():
    findings = scan(
        "EXTENSIONS=(\n"
        '  "ms-windows-ai-studio.windows-ai-studio"\n'
        '  "ms-python.python"\n'
        '  "ms-python.vscode-pylance"\n'
        ")\n"
        'for ext in "${EXTENSIONS[@]}"; do\n'
        '  code --install-extension "$ext" --force 2>/dev/null || true\n'
        "done\n"
        "$extensions = @(\n"
        '  "ms-vscode-remote.remote-containers",\n'
        '  "ms-vscode-remote.remote-wsl"\n'
        ")\n"
        "foreach ($ext in $extensions) {\n"
        "  code --install-extension $ext --force 2>&1 | Out-Null\n"
        "}\n",
        "script",
        "setup.sh",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "vscode-extension-install"
    }
    assert deps == {
        "ms-windows-ai-studio.windows-ai-studio",
        "ms-python.python",
        "ms-python.vscode-pylance",
        "ms-vscode-remote.remote-containers",
        "ms-vscode-remote.remote-wsl",
    }


def test_detects_vscode_extension_installs_from_powershell_wrapper():
    findings = scan(
        "function Install-VSCodeExtension {\n"
        "    param($ExtensionId, $ExtensionName)\n"
        "    code --install-extension $ExtensionId --force\n"
        "}\n"
        'Install-VSCodeExtension "ms-vscode-remote.remote-containers" "Dev Containers" | Out-Null\n'
        'Install-VSCodeExtension -ExtensionId "ms-vscode-remote.remote-wsl" -ExtensionName "WSL" | Out-Null\n',
        "script",
        "setup-devcontainer.ps1",
    )

    rows = [
        (f.line_number, f.extracted_dep)
        for f in findings
        if f.pattern_id == "vscode-extension-install"
    ]
    assert rows == [
        (5, "ms-vscode-remote.remote-containers"),
        (6, "ms-vscode-remote.remote-wsl"),
    ]


def test_vscode_extension_ignores_guidance_and_local_vsix():
    findings = scan(
        "# code --install-extension GitHub.copilot\n"
        "Write-Warn2 '  code --install-extension GitHub.copilot-chat'\n"
        '"""The actual install action: `code --install-extension <vsix> --force`."""\n'
        "& code --install-extension $vsix.FullName --force 2>&1 | Out-Null\n"
        "code --install-extension ./dist/workflow-vscode.vsix --force\n",
        "script",
        "setup-winapprun.ps1",
    )

    assert not any(f.pattern_id == "vscode-extension-install" for f in findings)


def test_vscode_extension_wrapper_ignores_function_body_and_local_values():
    findings = scan(
        "function Install-VSCodeExtension {\n"
        "    param($ExtensionId, $ExtensionName)\n"
        "    code --install-extension $ExtensionId --force\n"
        "}\n"
        'Write-Host "Install-VSCodeExtension ms-python.python"\n'
        'Install-VSCodeExtension $vsix.FullName "Local extension"\n'
        "Install-VSCodeExtension ./dist/workflow-vscode.vsix Local\n",
        "script",
        "setup-devcontainer.ps1",
    )

    assert not any(f.pattern_id == "vscode-extension-install" for f in findings)


def test_vscode_extension_ignores_non_control_markdown_example():
    findings = scan(
        "```bash\n"
        "code --install-extension ms-python.python\n"
        "```\n",
        "agent_instruction",
        "SETUP.md",
    )

    assert not any(f.pattern_id == "vscode-extension-install" for f in findings)


def test_detects_krew_plugin_install_in_workflow():
    findings = scan(
        "- name: Test krew install retina\n"
        "  run: |\n"
        "    kubectl krew install retina\n",
        "ci",
        ".github/workflows/release-validation.yaml",
    )

    rows = [
        f for f in findings
        if f.pattern_id == "krew-plugin-install"
    ]
    assert [(f.line_number, f.extracted_dep) for f in rows] == [(3, "retina")]


def test_detects_krew_plugin_install_with_flags():
    findings = scan(
        "krew install --manifest /tmp/plugin.yaml --archive=/tmp/plugin.tar.gz sample-plugin\n",
        "script",
        "setup.sh",
    )

    assert any(
        f.pattern_id == "krew-plugin-install"
        and f.extracted_dep == "sample-plugin"
        for f in findings
    )


def test_krew_plugin_install_ignores_comments_and_printed_guidance():
    findings = scan(
        "# kubectl krew install retina\n"
        'echo "kubectl krew install retina"\n'
        "kubectl krew install real-plugin\n",
        "script",
        "setup.sh",
    )

    deps = [
        f.extracted_dep
        for f in findings
        if f.pattern_id == "krew-plugin-install"
    ]
    assert deps == ["real-plugin"]


def test_krew_plugin_install_ignores_non_control_markdown_example():
    findings = scan(
        "# Setup\n\nRun `kubectl krew install retina` to try the optional plugin.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(
        f.pattern_id == "krew-plugin-install"
        for f in findings
    )


def test_detects_helm_remote_repo_chart_and_plugin_installs():
    findings = scan(
        "helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx\n"
        "RunOrExitOnFailure helm repo add --force-update stress "
        "https://azuresdkartifacts.z5.web.core.windows.net/stress/\n"
        'helm repo add osmo "$HELM_REPO_OSMO" >/dev/null 2>&1 || true\n'
        "helm pull oci://ghcr.io/microsoft/retina/charts/retina --version $TAG\n"
        "helm chart pull mcr.microsoft.com/k8s/asohelmchart:latest\n"
        "helm plugin install https://github.com/databus23/helm-diff --version v3.9.12\n",
        "script",
        "setup.sh",
    )

    by_pattern = {
        (f.pattern_id, f.extracted_dep)
        for f in findings
        if f.pattern_id.startswith("helm-")
    }
    assert ("helm-repo-add", "https://kubernetes.github.io/ingress-nginx") in by_pattern
    assert ("helm-repo-add", "https://azuresdkartifacts.z5.web.core.windows.net/stress/") in by_pattern
    assert ("helm-repo-add", "$HELM_REPO_OSMO") in by_pattern
    assert ("helm-chart-pull", "oci://ghcr.io/microsoft/retina/charts/retina") in by_pattern
    assert ("helm-chart-pull", "mcr.microsoft.com/k8s/asohelmchart:latest") in by_pattern
    assert ("helm-plugin-install", "https://github.com/databus23/helm-diff") in by_pattern


def test_helm_remote_artifacts_ignore_local_sources_and_guidance():
    findings = scan(
        "# helm repo add argo https://argoproj.github.io/argo-helm\n"
        'echo "helm pull oci://ghcr.io/example/chart"\n'
        "helm repo add stable https://charts.helm.sh/stable\n"
        "helm repo add bitnami https://charts.bitnami.com/bitnami\n"
        "helm repo add --force-update local file://$absAddonsPath\n"
        "helm plugin add (Join-Path $absAddonsPath file-plugin)\n"
        "helm pull ./charts/local\n"
        "helm repo add argo https://argoproj.github.io/argo-helm\n",
        "script",
        "setup.ps1",
    )

    rows = [
        (f.pattern_id, f.extracted_dep)
        for f in findings
        if f.pattern_id.startswith("helm-")
    ]
    assert rows == [("helm-repo-add", "https://argoproj.github.io/argo-helm")]


def test_helm_remote_artifacts_ignore_non_control_markdown_example():
    findings = scan(
        "# Setup\n\n"
        "Run `helm repo add argo https://argoproj.github.io/argo-helm` and "
        "`helm pull oci://ghcr.io/example/chart` before testing.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(
        f.pattern_id.startswith("helm-")
        for f in findings
    )


def test_dotnet_template_install_trims_markdown_code_span():
    findings = scan(
        "| WinUI templates | `dotnet new install Microsoft.WindowsAppSDK.WinUI.CSharp.Templates` |\n",
        "agent_instruction",
        "SKILL.md",
    )

    assert any(
        f.pattern_id == "dotnet-template-install"
        and f.extracted_dep == "Microsoft.WindowsAppSDK.WinUI.CSharp.Templates"
        for f in findings
    )
    assert not any(
        f.pattern_id == "dotnet-template-install"
        and f.extracted_dep.endswith("`")
        for f in findings
    )


def test_detects_powershell_install_module_literal_name():
    findings = scan(
        "Install-Module -Name Microsoft.Graph.Authentication -Force -AllowClobber -Scope CurrentUser\n",
        "script",
        "install.ps1",
    )

    assert any(
        f.pattern_id == "powershell-install-module"
        and f.extracted_dep == "Microsoft.Graph.Authentication"
        for f in findings
    )


def test_powershell_install_module_ignores_printed_error_guidance():
    findings = scan(
        'Write-Error "$module module is not installed. Please run: Install-Module -Name $module"\n'
        "Install-Module -Name SqlServer -Scope CurrentUser -Force\n",
        "script",
        "install.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "powershell-install-module"
    }
    assert deps == {"SqlServer"}


def test_powershell_package_management_detects_provider_and_package_installs():
    findings = scan(
        "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force\n"
        "Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory "
        "-RequiredVersion 3.19.8 -Source https://www.nuget.org/api/v2 "
        "-SkipDependencies -Scope CurrentUser\n",
        "script",
        "setup.ps1",
    )

    deps_by_pattern = {
        f.pattern_id: f.extracted_dep
        for f in findings
        if f.pattern_id in {
            "powershell-install-package-provider",
            "powershell-install-package",
        }
    }
    assert deps_by_pattern == {
        "powershell-install-package-provider": "NuGet",
        "powershell-install-package": "Microsoft.IdentityModel.Clients.ActiveDirectory",
    }


def test_powershell_package_management_ignores_local_helpers_and_guidance():
    findings = scan(
        "function Install-Package { }\n"
        '$installedDebugpyVersion = Install-Package "debugpy" $debugpyVersion $outdir\n'
        'Write-Host "Install-PackageProvider -Name NuGet -Force"\n',
        "script",
        "PreBuild.ps1",
    )

    assert not any(
        f.pattern_id in {
            "powershell-install-package-provider",
            "powershell-install-package",
        }
        for f in findings
    )


def test_powershell_install_module_reports_comma_separated_names():
    findings = scan(
        "Install-Module InvokeBuild, PowerShell-Yaml -ErrorAction Stop\n",
        "ci",
        ".github/workflows/publish-site.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "powershell-install-module"
    }
    assert deps == {"InvokeBuild", "PowerShell-Yaml"}


def test_powershell_install_module_detects_psresource_and_save_module():
    findings = scan(
        "Install-PSResource -Name Microsoft.WinGet.Client "
        "-Repository PSGallery -Version $cliVersion -TrustRepository -Quiet\n"
        "Save-Module -Name PSRule.Rules.MSFT.OSS -Repository PSGallery -Path out/repo/;\n",
        "github_action",
        "action.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "powershell-install-module"
    }
    assert deps == {"Microsoft.WinGet.Client", "PSRule.Rules.MSFT.OSS"}


def test_powershell_install_module_ignores_non_control_psresource_markdown_example():
    findings = scan(
        "# Setup\n\nRun `Install-PSResource -Name Microsoft.WinGet.Client` if needed.\n",
        "agent_instruction",
        "README.md",
    )

    assert not any(f.pattern_id == "powershell-install-module" for f in findings)


def test_powershell_install_module_ignores_inert_quoted_command_string():
    findings = scan(
        '"Install-Module -Name PowerShell-Yaml -RequiredVersion 0.4.7 -Force"\n'
        '$cmd = "Install-PSResource -Name Microsoft.WinGet.Client"\n',
        "script",
        "Test-PSModulePins.Tests.ps1",
    )

    assert not any(f.pattern_id == "powershell-install-module" for f in findings)


def test_powershell_install_module_ignores_quoted_fixture_values():
    findings = scan(
        "$cases = @{\n"
        "  'scripts/a.ps1' = "
        '"Install-Module -Name Pester -RequiredVersion 5.7.1 -Force"\n'
        "}\n"
        'Set-Content -Path scripts/b.ps1 -Value '
        '"Install-Module -Name PSScriptAnalyzer -RequiredVersion 1.21.0 -Force"\n',
        "script",
        "Test-PSModulePins.Tests.ps1",
    )

    assert not any(f.pattern_id == "powershell-install-module" for f in findings)


def test_powershell_install_module_keeps_pwsh_command_string():
    findings = scan(
        'pwsh -NoProfile -Command "Install-PSResource -Name Microsoft.WinGet.Client -TrustRepository"\n',
        "script",
        "setup.sh",
    )

    assert any(
        f.pattern_id == "powershell-install-module"
        and f.extracted_dep == "Microsoft.WinGet.Client"
        for f in findings
    )


def test_detects_powershell_install_module_foreach_literal_array():
    findings = scan(
        "foreach ($moduleName in @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Beta.Security')) {\n"
        "    Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser\n"
        "}\n",
        "script",
        "install.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "powershell-install-module"
    }
    assert deps == {"Microsoft.Graph.Authentication", "Microsoft.Graph.Beta.Security"}


def test_detects_powershell_install_module_foreach_single_literal():
    findings = scan(
        "foreach ($mod in 'Microsoft.Graph.Authentication') {\n"
        "    Install-Module -Name $mod -Force -AllowClobber -Scope CurrentUser\n"
        "}\n",
        "script",
        "install.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "powershell-install-module"
    }
    assert deps == {"Microsoft.Graph.Authentication"}


def test_detects_powershell_install_module_wrapper_call_literals():
    findings = scan(
        "function Resolve-Module($moduleName) {\n"
        "    Install-Module $moduleName -Force -Scope CurrentUser\n"
        "}\n"
        "Resolve-Module -moduleName Az.Resources\n"
        "Resolve-Module SqlServer\n",
        "script",
        "install.ps1",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "powershell-install-module"
    }
    assert deps == {"Az.Resources", "SqlServer"}


def test_powershell_install_module_ignores_unresolved_function_parameter():
    findings = scan(
        "function Install-ModuleIfNeeded {\n"
        "    param([string]$ModuleName)\n"
        "    Install-Module -Name $ModuleName -Force -Scope CurrentUser\n"
        "}\n",
        "script",
        "install.ps1",
    )

    assert not any(
        f.pattern_id == "powershell-install-module"
        and f.extracted_dep == "$ModuleName"
        for f in findings
    )


def test_detects_windows_package_installs_in_agent_markdown_headings():
    findings = scan(
        "# install: winget install Microsoft.WinAppCli\n",
        "agent_instruction",
        "AGENTS.md",
    )

    assert any(
        f.pattern_id == "winget-command-install"
        and f.extracted_dep == "Microsoft.WinAppCli"
        for f in findings
    )


def test_ignores_printed_winget_install_hint():
    findings = scan(
        "echo winget install failed\n"
        'Write-Host "winget install Microsoft.WinAppCli"\n',
        "script",
        "publish.cmd",
    )

    assert not any(f.pattern_id == "winget-command-install" for f in findings)


def test_ignores_install_hint_stored_in_missing_message_array():
    findings = scan(
        'MISSING+=("PowerShell 7+ (pwsh) - macOS: brew install powershell")\n'
        "brew install azure-cli\n",
        "script",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "brew-install-ci"
    }
    assert deps == {"azure-cli"}


def test_ignores_inline_throw_winget_install_failure():
    findings = scan(
        'if ($LASTEXITCODE -ne 0) { throw "winget install Microsoft.WinAppCli failed" }\n',
        "script",
        "bootstrap.ps1",
    )

    assert not any(f.pattern_id == "winget-command-install" for f in findings)


def test_keeps_executable_winget_install_after_print_command():
    findings = scan(
        "echo starting && winget install Microsoft.WinAppCli\n",
        "script",
        "publish.cmd",
    )

    assert any(
        f.pattern_id == "winget-command-install"
        and f.extracted_dep == "Microsoft.WinAppCli"
        for f in findings
    )


def test_keeps_winget_install_inside_print_command_substitution():
    findings = scan(
        'echo "$(winget install Microsoft.WinAppCli)"\n',
        "script",
        "publish.cmd",
    )

    assert any(
        f.pattern_id == "winget-command-install"
        and f.extracted_dep == "Microsoft.WinAppCli"
        for f in findings
    )


def test_detects_dynamic_nuget_restore_from_generated_package_reference():
    findings = scan(
        "3. Downloads the package via `dotnet restore` if not cached.\n"
        "$versions = Invoke-RestMethod -Uri $versionsUrl\n"
        "$Version = $versions.latest\n"
        "$project = @\"\n"
        '<PackageReference Include="$PackageId" Version="$Version" />\n'
        "\"@\n"
        "$restoreResult = & dotnet restore $csprojPath --configfile $nugetConfigPath\n"
        'Write-Warning "dotnet restore failed for $PackageId $Version"\n',
        "script",
        "generate-package-json.ps1",
    )

    dynamic_findings = [f for f in findings if f.pattern_id == "dotnet-dynamic-restore"]
    assert len(dynamic_findings) == 1
    assert dynamic_findings[0].extracted_dep == "$PackageId@$Version"
    assert dynamic_findings[0].severity == Severity.HIGH


def test_ordinary_dotnet_restore_is_not_dynamic_nuget_restore():
    findings = scan("dotnet restore src/App.csproj\n", "script", "restore.ps1")

    assert not any(f.pattern_id == "dotnet-dynamic-restore" for f in findings)
