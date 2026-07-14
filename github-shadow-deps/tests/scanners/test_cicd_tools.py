"""Tests for CICDToolScanner (GitHub Actions pinning)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Severity
from github_inventory.scanners.cicd_tools import CICDToolScanner


def scan(content: str, rel_path: str | None = None):
    scanner = CICDToolScanner(Config())
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(content)
        p = Path(f.name)
    target = FileTarget(path=p, rel_path=rel_path or p.name, file_type="ci")
    return scanner.scan_file(target)


def test_flags_action_on_main_branch():
    findings = scan("      - uses: actions/checkout@main\n")
    assert any(f.pattern_id == "action-on-mutable-branch" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_flags_action_on_master_branch():
    findings = scan("      - uses: org/action@master\n")
    assert any(f.pattern_id == "action-on-mutable-branch" for f in findings)


def test_flags_unpinned_tag():
    findings = scan("      - uses: actions/setup-node@v4\n")
    assert any(f.pattern_id == "unpinned-github-action-1p" for f in findings)
    tag_findings = [f for f in findings if f.pattern_id == "unpinned-github-action-1p"]
    assert all(f.severity == Severity.MEDIUM for f in tag_findings)


def test_flags_unpinned_3p_tag():
    findings = scan("      - uses: chromaui/action@v1\n")
    assert any(f.pattern_id == "unpinned-github-action-3p" for f in findings)
    tag_findings = [f for f in findings if f.pattern_id == "unpinned-github-action-3p"]
    assert all(f.severity == Severity.HIGH for f in tag_findings)


def test_reusable_workflow_not_double_counted_as_3p_action():
    findings = scan(
        "      - uses: microsoft/azurelinux/.github/workflows/spec-review.yml@4.0\n"
    )
    pattern_ids = [f.pattern_id for f in findings]
    assert "reusable-workflow-unpinned" in pattern_ids
    assert "unpinned-github-action-3p" not in pattern_ids


@pytest.mark.parametrize("runner", ["ubuntu-latest", "windows-latest", "macos-latest"])
def test_flags_mutable_github_hosted_runner(runner):
    findings = scan(
        f"    runs-on: '{runner}'\n",
        rel_path=".github/workflows/ci.yml",
    )
    runner_findings = [f for f in findings if f.pattern_id == "mutable-github-runner"]
    assert len(runner_findings) == 1
    assert runner_findings[0].extracted_dep == runner
    assert runner_findings[0].severity == Severity.MEDIUM


@pytest.mark.parametrize("runner", ["8-core-ubuntu-latest", "ubuntu-slim"])
def test_flags_extended_mutable_github_hosted_runner_labels(runner):
    findings = scan(
        f"    runs-on: {runner}\n",
        rel_path=".github/workflows/ci.yml",
    )
    assert any(
        f.pattern_id == "mutable-github-runner" and f.extracted_dep == runner
        for f in findings
    )


def test_flags_mutable_runner_inside_expression():
    findings = scan(
        "    runs-on: ${{ github.repository == 'x/y' && '8-core-ubuntu-latest' || 'ubuntu-latest' }}\n",
        rel_path=".github/workflows/ci.yml",
    )

    deps = {
        f.extracted_dep for f in findings
        if f.pattern_id == "mutable-github-runner"
    }
    assert deps == {"8-core-ubuntu-latest", "ubuntu-latest"}


def test_flags_all_mutable_runner_labels_inside_conditional_expression():
    findings = scan(
        "    runs-on: ${{ (matrix.language == 'swift' && 'macos-latest') || 'ubuntu-latest' }}\n",
        rel_path=".github/workflows/codeql.yml",
    )

    deps = {
        f.extracted_dep for f in findings
        if f.pattern_id == "mutable-github-runner"
    }
    assert deps == {"macos-latest", "ubuntu-latest"}


def test_does_not_flag_stable_or_self_hosted_runner():
    findings = scan(
        "    runs-on: ubuntu-24.04\n    runs-on: self-hosted\n",
        rel_path=".github/workflows/ci.yml",
    )
    assert [f for f in findings if f.pattern_id == "mutable-github-runner"] == []


def test_does_not_flag_runner_in_non_workflow_template():
    findings = scan("    runs-on: ubuntu-latest\n", rel_path="example-config.yml.template")
    assert [f for f in findings if f.pattern_id == "mutable-github-runner"] == []


@pytest.mark.parametrize("image", ["ubuntu-latest", "windows-latest", "macos-latest", "macOS-latest"])
def test_flags_azure_pipelines_mutable_hosted_images(image):
    findings = scan(
        "pool:\n"
        f"  vmImage: '{image}'\n",
        rel_path="azure-pipelines.yml",
    )

    image_findings = [
        f for f in findings
        if f.pattern_id == "azure-pipelines-mutable-image"
    ]
    assert len(image_findings) == 1
    assert image_findings[0].extracted_dep == image
    assert image_findings[0].severity == Severity.MEDIUM


def test_flags_azure_pipelines_pool_image_key_mutable_label():
    findings = scan(
        "pool:\n"
        "  name: Azure Pipelines\n"
        "  image: macOS-latest\n"
        "  os: macOS\n",
        rel_path="azure-pipelines.yml",
    )

    assert any(
        f.pattern_id == "azure-pipelines-mutable-image"
        and f.extracted_dep == "macOS-latest"
        for f in findings
    )


def test_azure_pipelines_mutable_image_ignores_github_workflow_and_fixed_pool_images():
    findings = scan(
        "jobs:\n"
        "  test:\n"
        "    services:\n"
        "      redis:\n"
        "        image: ubuntu-latest\n",
        rel_path=".github/workflows/ci.yml",
    )
    findings.extend(scan(
        "pool:\n"
        "  image: windows-2022-secure\n"
        "  vmImage: ubuntu-24.04\n",
        rel_path="azure-pipelines.yml",
    ))

    assert [f for f in findings if f.pattern_id == "azure-pipelines-mutable-image"] == []


def test_does_not_flag_sha_pinned_action():
    sha = "a" * 40
    findings = scan(f"      - uses: actions/checkout@{sha}\n")
    action_findings = [f for f in findings if "action" in f.pattern_id]
    assert action_findings == [], f"SHA-pinned action incorrectly flagged: {action_findings}"


def test_does_not_flag_local_action():
    findings = scan("      - uses: ./local-action\n")
    action_findings = [f for f in findings if "action" in f.pattern_id]
    assert action_findings == []


def test_flags_tool_download_in_run():
    findings = scan('      run: curl -LO "https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl"\n')
    assert any(f.pattern_id == "tool-download-in-ci" for f in findings)


def test_flags_docker_container_action_image():
    findings = scan(
        "      - uses: docker://rhysd/actionlint:1.7.12\n",
        rel_path=".github/workflows/consistency.yml",
    )

    assert any(
        f.pattern_id == "gha-docker-action-image"
        and f.extracted_dep == "rhysd/actionlint:1.7.12"
        for f in findings
    )


def test_flags_docker_container_action_image_digest():
    digest = "a" * 64
    findings = scan(
        f"      - uses: docker://ghcr.io/org/action@sha256:{digest}\n",
        rel_path=".github/workflows/ci.yml",
    )

    assert any(
        f.pattern_id == "gha-docker-action-image"
        and f.extracted_dep == f"ghcr.io/org/action@sha256:{digest}"
        for f in findings
    )


def test_dedupes_repeated_same_file_dependencies():
    findings = scan(
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/checkout@v4\n"
        "      run: curl -LO https://example.com/tool\n"
        "      run: curl -LO https://example.com/tool\n",
        rel_path=".github/workflows/generated.yml",
    )

    checkout_findings = [
        f for f in findings
        if f.pattern_id == "unpinned-github-action-1p"
        and f.extracted_dep == "actions/checkout@v4"
    ]
    download_findings = [
        f for f in findings
        if f.pattern_id == "tool-download-in-ci"
        and f.extracted_dep == "https://example.com/tool"
    ]
    assert len(checkout_findings) == 1
    assert len(download_findings) == 1


def test_keeps_distinct_same_file_action_dependencies():
    findings = scan(
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-node@v4\n",
        rel_path=".github/workflows/ci.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "unpinned-github-action-1p"
    }
    assert deps == {"actions/checkout@v4", "actions/setup-node@v4"}


def test_tool_download_keeps_github_expression_inside_url():
    url = (
        "https://github.com/mstorsjo/llvm-mingw/releases/download/20220906/"
        "${{ env.LLVM-MINGW-TOOLCHAIN-NAME }}.tar.xz"
    )
    findings = scan(
        f"      run: curl -L -o ${{{{ env.LLVM-MINGW-TOOLCHAIN-NAME }}}}.tar.xz {url}\n"
    )

    assert any(
        f.pattern_id == "tool-download-in-ci"
        and f.extracted_dep == url
        for f in findings
    )


def test_tool_download_detects_bitsadmin_download_in_matrix_value():
    url = (
        "https://download.unity3d.com/download_unity/${{ needs.compute.outputs.UNITY_HASH }}/"
        "Windows64EditorInstaller/UnitySetup64-${{ needs.compute.outputs.UNITY_FULL_VERSION }}.exe"
    )
    findings = scan(
        f'      download: cmd /c bitsadmin /TRANSFER unity /DOWNLOAD /PRIORITY foreground "{url}" "%CD%\\unitysetup.exe"\n'
    )

    assert any(
        f.pattern_id == "tool-download-in-ci"
        and f.extracted_dep == url
        for f in findings
    )


def test_detects_taiki_install_action_tool_input():
    findings = scan(
        "      - name: Install nextest\n"
        "        uses: taiki-e/install-action@v2\n"
        "        with:\n"
        "          tool: cargo-nextest\n",
        rel_path=".github/workflows/ci.yml",
    )

    assert any(
        f.pattern_id == "github-action-tool-installer"
        and f.extracted_dep == "cargo-nextest"
        for f in findings
    )


def test_detects_taiki_cache_cargo_install_action_tool_input():
    findings = scan(
        "      - uses: taiki-e/cache-cargo-install-action@v3\n"
        "        with:\n"
        "          tool: taplo-cli\n",
        rel_path=".github/workflows/code-formatting-check.yaml",
    )

    assert any(
        f.pattern_id == "github-action-tool-installer"
        and f.extracted_dep == "taplo-cli"
        for f in findings
    )


def test_detects_taiki_cache_cargo_install_action_git_source_with_rev():
    findings = scan(
        "      - name: Install taplo-cli from pinned revision b673b44d\n"
        "        uses: taiki-e/cache-cargo-install-action@v3\n"
        "        with:\n"
        "          tool: taplo-cli\n"
        "          git: https://github.com/tamasfe/taplo\n"
        "          rev: b673b44d\n"
        "          locked: true\n",
        rel_path=".github/workflows/code-formatting-check.yaml",
    )

    assert any(
        f.pattern_id == "github-action-tool-installer"
        and f.extracted_dep == "taplo-cli"
        for f in findings
    )
    assert any(
        f.pattern_id == "github-action-tool-installer-git-source"
        and f.extracted_dep == "https://github.com/tamasfe/taplo#rev=b673b44d"
        for f in findings
    )


def test_detects_taiki_install_action_git_source_with_branch():
    findings = scan(
        "      - uses: taiki-e/install-action@v2\n"
        "        with:\n"
        "          tool: cargo-example\n"
        "          git: https://github.com/example/tool\n"
        "          branch: release\n",
        rel_path=".github/workflows/ci.yml",
    )

    assert any(
        f.pattern_id == "github-action-tool-installer-git-source"
        and f.extracted_dep == "https://github.com/example/tool#branch=release"
        for f in findings
    )


def test_taiki_install_action_ignores_dynamic_git_source():
    findings = scan(
        "      - uses: taiki-e/cache-cargo-install-action@v3\n"
        "        with:\n"
        "          tool: taplo-cli\n"
        "          git: ${{ inputs.taplo_repo }}\n"
        "          rev: ${{ inputs.taplo_rev }}\n",
        rel_path=".github/workflows/code-formatting-check.yaml",
    )

    assert not any(
        f.pattern_id == "github-action-tool-installer-git-source"
        for f in findings
    )
    assert any(
        f.pattern_id == "github-action-tool-installer"
        and f.extracted_dep == "taplo-cli"
        for f in findings
    )


def test_taiki_install_action_splits_literal_tool_list():
    findings = scan(
        "      - uses: taiki-e/install-action@v2\n"
        "        with:\n"
        "          tools: cargo-nextest, cargo-llvm-cov@0.6.17\n",
        rel_path=".github/workflows/ci.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "github-action-tool-installer"
    }
    assert {"cargo-nextest", "cargo-llvm-cov@0.6.17"} <= deps


def test_taiki_install_action_ignores_dynamic_tool_expression():
    findings = scan(
        "      - name: Install Cargo Tools\n"
        "        uses: taiki-e/install-action@v2.81.8\n"
        "        with:\n"
        "          tool: ${{ steps.expand.outputs.cargo_tools }}\n",
        rel_path=".github/actions/setup/action.yml",
    )

    assert not any(
        f.pattern_id == "github-action-tool-installer"
        for f in findings
    )


def test_tool_download_keeps_shell_command_substitution_inside_url():
    url = (
        "https://packages.microsoft.com/config/ubuntu/"
        "$(grep VERSION_ID /etc/os-release | cut -d '\"' -f 2)"
        "/packages-microsoft-prod.deb"
    )
    findings = scan(f"      run: curl -fsSL -O {url}\n")

    assert any(
        f.pattern_id == "tool-download-in-ci"
        and f.extracted_dep == url
        for f in findings
    )


def test_tool_download_ignores_openapi_metadata_documents():
    findings = scan(
        "      run: |\n"
        "        curl -o petstore.yaml https://raw.githubusercontent.com/OAI/OpenAPI-Specification/refs/heads/main/petstore.yaml\n"
        "        curl -o twitter.json https://raw.githubusercontent.com/APIs-guru/openapi-directory/gh-pages/v2/specs/twitter.com/current/2.61/openapi.json\n"
    )

    assert not any(f.pattern_id == "tool-download-in-ci" for f in findings)


def test_fixture_github_actions_yml():
    fixture = (
        Path(__file__).parent.parent
        / "fixtures"
        / ".github"
        / "workflows"
        / "github_actions.yml"
    )
    scanner = CICDToolScanner(Config())
    target = FileTarget(path=fixture, rel_path="github_actions.yml", file_type="ci")
    findings = scanner.scan_file(target)
    pattern_ids = {f.pattern_id for f in findings}
    assert "action-on-mutable-branch" in pattern_ids
    assert "unpinned-github-action-1p" in pattern_ids or "unpinned-github-action-3p" in pattern_ids
