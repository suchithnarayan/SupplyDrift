"""Tests for GitDependencyScanner."""
from __future__ import annotations

from pathlib import Path
import tempfile

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.git_dependencies import GitDependencyScanner


def scan(content: str, file_type: str = "ci", name: str = "test.yml"):
    scanner = GitDependencyScanner(Config())
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        target = FileTarget(path=p, rel_path=name, file_type=file_type)
        return scanner.scan_file(target)


def test_go_get_skips_flags_and_local_package_patterns():
    findings = scan("go get -t -v ./...\n")

    assert not any(f.pattern_id == "go-get" for f in findings)


def test_go_get_detects_external_module_after_flags():
    findings = scan("go get -u github.com/example/tool\n")

    assert any(
        f.pattern_id == "go-get" and f.extracted_dep == "github.com/example/tool"
        for f in findings
    )


def test_go_get_ignores_ci_workflow_name_metadata():
    findings = scan("name: Build and test Go Get Started sample\n")

    assert not any(f.pattern_id == "go-get" for f in findings)


def test_git_clone_detects_short_options_before_repo():
    findings = scan("git clone -b v1.2.3 git://code.qt.io/qt/qt5.git qt6\n", file_type="script")

    assert any(
        f.pattern_id == "git-clone" and f.extracted_dep == "git://code.qt.io/qt/qt5.git"
        for f in findings
    )


def test_git_clone_detects_bare_git_transport():
    findings = scan("git clone --bare git://git.freedesktop.org/git/pixman\n", file_type="script")

    assert any(
        f.pattern_id == "git-clone" and f.extracted_dep == "git://git.freedesktop.org/git/pixman"
        for f in findings
    )


def test_git_clone_ignores_lowercase_readme_markdown_fence():
    findings = scan(
        "Clone locally:\n\n"
        "```bash\n"
        "git clone https://github.com/example/project.git\n"
        "```\n",
        file_type="agent_instruction",
        name="readme.md",
    )

    assert not any(f.pattern_id == "git-clone" for f in findings)


def test_git_clone_detects_python_subprocess_shell_command():
    findings = scan(
        "import subprocess\n"
        "subprocess.run('sudo git clone https://github.com/akopytov/sysbench.git', shell=True, check=True)\n",
        file_type="source_code",
        name="configure.py",
    )

    assert any(
        f.pattern_id == "git-clone"
        and f.extracted_dep == "https://github.com/akopytov/sysbench.git"
        for f in findings
    )


def test_git_clone_ignores_non_executed_python_string():
    findings = scan(
        'print("sudo git clone https://github.com/akopytov/sysbench.git")\n',
        file_type="source_code",
        name="configure.py",
    )

    assert not any(f.pattern_id == "git-clone" for f in findings)


def test_javascript_source_shell_detects_git_remote_add():
    findings = scan(
        "const cp = require('child_process');\n"
        "cp.execSync(`git remote add origin https://github.com/${repoOwner}/${repoName}.git`);\n",
        file_type="source_code",
        name="translations_auto_pr.js",
    )

    assert any(
        f.pattern_id == "git-remote-add"
        and f.extracted_dep == "https://github.com/${repoOwner}/${repoName}.git"
        and f.line_number == 2
        for f in findings
    )


def test_javascript_source_shell_ignores_test_path_git_remote_add():
    findings = scan(
        "const cp = require('child_process');\n"
        "cp.execSync(`git remote add origin https://github.com/${repoOwner}/${repoName}.git`);\n",
        file_type="source_code",
        name="tests/translations_auto_pr.test.js",
    )

    assert not any(f.pattern_id == "git-remote-add" for f in findings)


def test_pip_git_install_stops_at_closing_quote():
    findings = scan(
        'pip install "dion @ git+https://github.com/microsoft/dion.git"\n',
        file_type="ci",
    )

    assert any(
        f.pattern_id == "pip-git-install"
        and f.extracted_dep == "git+https://github.com/microsoft/dion.git"
        for f in findings
    )


def test_pip_git_install_detects_dockerfile_install():
    findings = scan(
        'RUN pip3 install "git+https://github.com/openai/whisper.git"\n',
        file_type="dockerfile",
        name="Dockerfile",
    )

    assert any(
        f.pattern_id == "pip-git-install"
        and f.extracted_dep == "git+https://github.com/openai/whisper.git"
        for f in findings
    )


def test_pip_git_install_ignores_non_control_markdown_example():
    findings = scan(
        "# Install\n\n"
        "```bash\n"
        "pip install git+https://github.com/microsoft/conductor.git\n"
        "```\n",
        file_type="agent_instruction",
        name="README.md",
    )

    assert not any(f.pattern_id == "pip-git-install" for f in findings)


def test_pip_git_install_does_not_cross_shell_command_separator():
    findings = scan(
        'pip install uv && uvx --from "git+https://github.com/microsoft/benchmark-qed" benchmark-qed\n',
        file_type="agent_instruction",
        name="SKILL.md",
    )

    assert not any(
        f.pattern_id == "pip-git-install"
        and f.extracted_dep == "git+https://github.com/microsoft/benchmark-qed"
        for f in findings
    )


def test_pip_git_install_ignores_package_config_comment():
    findings = scan(
        '# `pip install "dion @ git+https://github.com/microsoft/dion.git"`\n',
        file_type="package_config",
        name="setup.py",
    )

    assert not any(f.pattern_id == "pip-git-install" for f in findings)


def test_git_clone_uses_repo_url_after_command_substitution_option():
    findings = scan(
        (
            'RUN git clone --depth 1 --branch $(curl --silent '
            '"https://api.github.com/repos/microsoft/lisa/releases/latest" '
            '| grep tag_name) https://github.com/microsoft/lisa.git /src/lisa\n'
        ),
        file_type="dockerfile",
        name="Dockerfile",
    )

    git_clone = next(f for f in findings if f.pattern_id == "git-clone")
    assert git_clone.extracted_dep == "https://github.com/microsoft/lisa.git"


def test_git_clone_ignores_later_same_line_command_urls():
    findings = scan(
        "git clone https://github.com/example/project.git && curl https://example.com/install.sh\n",
        file_type="script",
    )

    git_clone = next(f for f in findings if f.pattern_id == "git-clone")
    assert git_clone.extracted_dep == "https://github.com/example/project.git"


def test_git_clone_dedupes_repeated_same_file_repo():
    findings = scan(
        "git clone https://github.com/example/project.git\n"
        "git clone https://github.com/example/project.git\n"
        "git clone https://github.com/example/other.git\n",
        file_type="agent_instruction",
        name="README.md",
    )

    deps = [
        f.extracted_dep for f in findings
        if f.pattern_id == "git-clone"
    ]
    assert deps == [
        "https://github.com/example/project.git",
        "https://github.com/example/other.git",
    ]


def test_git_clone_ignores_non_control_markdown_fenced_example():
    findings = scan(
        "## Setup\n\n"
        "```bash\n"
        "git clone https://github.com/example/project.git\n"
        "```\n",
        file_type="agent_instruction",
        name="agent-guide/README.md",
    )

    assert not any(f.pattern_id == "git-clone" for f in findings)


def test_git_clone_ignores_non_control_markdown_indented_example():
    findings = scan(
        "Open Terminal and run:\n\n"
        "    git clone https://github.com/example/project.git\n",
        file_type="agent_instruction",
        name="agent-guide/MAC-README.md",
    )

    assert not any(f.pattern_id == "git-clone" for f in findings)


def test_git_clone_ignores_non_control_markdown_inline_code_example():
    findings = scan(
        "2. Clone your fork: `git clone https://github.com/example/project.git`\n",
        file_type="agent_instruction",
        name="agent-guide/CONTRIBUTING.md",
    )

    assert not any(f.pattern_id == "git-clone" for f in findings)


def test_git_clone_detects_skill_markdown_fenced_instruction():
    findings = scan(
        "Bootstrap the workspace:\n\n"
        "```bash\n"
        "git clone https://github.com/example/project.git\n"
        "```\n",
        file_type="agent_instruction",
        name="SKILL.md",
    )

    assert any(
        f.pattern_id == "git-clone"
        and f.extracted_dep == "https://github.com/example/project.git"
        and f.line_number == 4
        for f in findings
    )


def test_git_remote_add_trims_wrapping_command_string_quote():
    findings = scan(
        "Invoke 'git remote add tools https://github.com/azure/azure-sdk-tools.git'\n",
        file_type="script",
        name="eng/scripts/Update-EngCommon.ps1",
    )

    assert any(
        f.pattern_id == "git-remote-add"
        and f.extracted_dep == "https://github.com/azure/azure-sdk-tools.git"
        for f in findings
    )


def test_git_remote_add_preserves_github_actions_expression_url():
    findings = scan(
        "git remote add pr https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git\n",
        file_type="ci",
        name=".github/workflows/python-integration.yml",
    )

    assert any(
        f.pattern_id == "git-remote-add"
        and f.extracted_dep == "https://github.com/${{ github.event.pull_request.head.repo.full_name }}.git"
        for f in findings
    )


def test_git_remote_add_preserves_split_github_actions_expression_url():
    findings = scan(
        "git remote add upstream https://github.com/${{ inputs.owner }}/${{ inputs.repo }}\n",
        file_type="ci",
        name=".github/workflows/reusable.yml",
    )

    assert any(
        f.pattern_id == "git-remote-add"
        and f.extracted_dep == "https://github.com/${{ inputs.owner }}/${{ inputs.repo }}"
        for f in findings
    )


def test_git_remote_add_detects_quoted_github_actions_expression_url():
    findings = scan(
        'git remote add upstream "https://github.com/${{ github.repository }}"\n',
        file_type="ci",
        name=".github/workflows/ci.yml",
    )

    assert any(
        f.pattern_id == "git-remote-add"
        and f.extracted_dep == "https://github.com/${{ github.repository }}"
        for f in findings
    )


def test_github_actions_checkout_repository_input_detects_external_repo():
    findings = scan(
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          repository: microsoft/vcpkg\n"
        "          path: vcpkg\n",
        file_type="ci",
        name=".github/workflows/ci.yml",
    )

    assert any(
        f.pattern_id == "github-actions-checkout-repository"
        and f.extracted_dep == "microsoft/vcpkg"
        and f.line_number == 6
        for f in findings
    )


def test_github_actions_checkout_repository_input_includes_static_ref():
    findings = scan(
        "steps:\n"
        "  - name: checkout templates\n"
        "    uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "    with:\n"
        "      repository: microsoft/vscode-github-triage-actions\n"
        "      ref: stable\n",
        file_type="ci",
        name=".github/workflows/stale.yml",
    )

    assert any(
        f.pattern_id == "github-actions-checkout-repository"
        and f.extracted_dep == "microsoft/vscode-github-triage-actions@stable"
        for f in findings
    )


def test_github_actions_checkout_repository_input_ignores_dynamic_repository():
    findings = scan(
        "steps:\n"
        "  - uses: actions/checkout@v4\n"
        "    with:\n"
        "      repository: ${{ inputs.repo }}\n"
        "      ref: ${{ inputs.ref }}\n",
        file_type="ci",
        name=".github/workflows/reusable.yml",
    )

    assert not any(f.pattern_id == "github-actions-checkout-repository" for f in findings)


def test_azure_pipelines_repository_resource_detects_named_repo_with_ref():
    findings = scan(
        "resources:\n"
        "  repositories:\n"
        "  - repository: 1ESPipelineTemplates\n"
        "    type: git\n"
        "    name: 1ESPipelineTemplates/1ESPipelineTemplates\n"
        "    ref: refs/tags/release\n",
        file_type="ci",
        name="azure-pipelines.yml",
    )

    assert any(
        f.pattern_id == "azure-pipelines-repository-resource"
        and f.extracted_dep == "1ESPipelineTemplates/1ESPipelineTemplates@refs/tags/release"
        and f.line_number == 5
        for f in findings
    )


def test_azure_pipelines_repository_resource_detects_internal_repo_name():
    findings = scan(
        "resources:\n"
        "  repositories:\n"
        "    - repository: CloudBuild\n"
        "      type: git\n"
        "      name: CloudBuild\n",
        file_type="ci",
        name=".azdo/maintenance/azure-pipelines.yml",
    )

    assert any(
        f.pattern_id == "azure-pipelines-repository-resource"
        and f.extracted_dep == "CloudBuild"
        for f in findings
    )


def test_azure_pipelines_repository_resource_ignores_exclusion_lists_and_dynamic_names():
    findings = scan(
        "sourceRepositoriesToScan:\n"
        "  exclude:\n"
        "    - repository: AzureDevOps\n"
        "resources:\n"
        "  repositories:\n"
        "  - repository: Dynamic\n"
        "    type: git\n"
        "    name: ${{ parameters.repository }}\n",
        file_type="ci",
        name="azure-pipelines.yml",
    )

    assert not any(f.pattern_id == "azure-pipelines-repository-resource" for f in findings)


def test_pyproject_git_source_only_applies_to_pyproject_toml():
    cargo_findings = scan(
        'russh = { git = "https://github.com/microsoft/vscode-russh" }\n',
        file_type="package_config",
        name="Cargo.toml",
    )

    assert not any(f.pattern_id == "pyproject-git-source" for f in cargo_findings)

    pyproject_findings = scan(
        'tool = { git = "https://github.com/example/tool" }\n',
        file_type="package_config",
        name="pyproject.toml",
    )

    assert any(
        f.pattern_id == "pyproject-git-source"
        and f.extracted_dep == "https://github.com/example/tool"
        for f in pyproject_findings
    )


def test_pyproject_git_source_ignores_default_pypi_index_url():
    findings = scan(
        '[[tool.uv.index]]\n'
        'name = "pypi"\n'
        'url = "https://pypi.org/simple"\n',
        file_type="package_config",
        name="pyproject.toml",
    )

    assert not any(f.pattern_id == "pyproject-git-source" for f in findings)


def test_pyproject_git_source_ignores_test_pypi_index_and_publish_url():
    findings = scan(
        '[[tool.uv.index]]\n'
        'name = "testpypi"\n'
        'url = "https://test.pypi.org/simple/"\n'
        '[tool.pdm.publish]\n'
        'publish-url = "https://test.pypi.org/legacy/"\n',
        file_type="package_config",
        name="pyproject.toml",
    )

    assert not any(f.pattern_id == "pyproject-git-source" for f in findings)


def test_pyproject_git_source_ignores_uv_package_index_url():
    findings = scan(
        '[project]\n'
        'dependencies = ["torch==2.12.0"]\n'
        '[[tool.uv.index]]\n'
        'name = "pytorch-cpu"\n'
        'url = "https://download.pytorch.org/whl/cpu"\n'
        'explicit = true\n'
        '[tool.uv.sources]\n'
        'torch = { index = "pytorch-cpu" }\n',
        file_type="package_config",
        name="pyproject.toml",
    )

    assert not any(f.pattern_id == "pyproject-git-source" for f in findings)


def test_pyproject_git_source_detects_standalone_url_dependency():
    findings = scan(
        'tool = { url = "https://github.com/example/tool/archive/refs/tags/v1.0.0.zip" }\n',
        file_type="package_config",
        name="pyproject.toml",
    )

    assert any(
        f.pattern_id == "pyproject-git-source"
        and f.extracted_dep == "https://github.com/example/tool/archive/refs/tags/v1.0.0.zip"
        for f in findings
    )


def test_git_clone_detects_agent_instruction_clone():
    findings = scan(
        "Clone with git clone --depth 1 https://github.com/microsoft/aspire.git /tmp/aspire\n",
        file_type="agent_instruction",
        name="SKILL.md",
    )

    assert any(
        f.pattern_id == "git-clone"
        and f.extracted_dep == "https://github.com/microsoft/aspire.git"
        for f in findings
    )
