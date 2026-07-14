"""Tests for RegistryConfigScanner."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.scanners.registry_config import RegistryConfigScanner


def scan(content: str, file_type: str = "nuget_config", name: str = "NuGet.config"):
    scanner = RegistryConfigScanner(Config())
    target = FileTarget(path=Path(name), rel_path=name, file_type=file_type)
    return scanner.scan_file_content(target, content, content.splitlines())


def test_nuget_org_feed_is_not_custom_feed():
    findings = scan(
        """<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
"""
    )

    assert not any(f.pattern_id == "nuget-custom-feed" for f in findings)


def test_nonstandard_nuget_feed_is_reported():
    findings = scan(
        """<configuration>
  <packageSources>
    <add key="internal" value="https://packages.example.com/nuget/v3/index.json" />
  </packageSources>
</configuration>
"""
    )

    assert any(
        f.pattern_id == "nuget-custom-feed"
        and f.extracted_dep == "https://packages.example.com/nuget/v3/index.json"
        for f in findings
    )


def test_nuget_feed_inside_xml_comment_is_not_reported():
    findings = scan(
        """<configuration>
  <packageSources>
    <add key="internal" value="https://packages.example.com/nuget/v3/index.json" />
    <!-- <add key="old" value="https://old.example.com/nuget/v3/index.json" /> -->
  </packageSources>
</configuration>
"""
    )

    deps = {
        f.extracted_dep for f in findings
        if f.pattern_id == "nuget-custom-feed"
    }
    assert "https://packages.example.com/nuget/v3/index.json" in deps
    assert "https://old.example.com/nuget/v3/index.json" not in deps


def test_canonical_npm_global_registry_is_not_reported():
    findings = scan(
        "registry=https://registry.npmjs.org/\n",
        "npmrc",
        ".npmrc",
    )

    assert not any(f.pattern_id == "npmrc-global-registry" for f in findings)


def test_canonical_npmjs_com_global_registry_is_not_reported():
    findings = scan(
        "registry=https://registry.npmjs.com/\n",
        "npmrc",
        ".npmrc",
    )

    assert not any(f.pattern_id == "npmrc-global-registry" for f in findings)


def test_nonstandard_npm_global_registry_is_reported():
    findings = scan(
        "registry=https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public-npm/npm/registry/\n",
        "npmrc",
        ".npmrc",
    )

    assert any(
        f.pattern_id == "npmrc-global-registry"
        and f.extracted_dep == "https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public-npm/npm/registry/"
        for f in findings
    )


def test_npm_auth_token_is_discarded_before_finding_construction():
    canary = "npm_supplydrift_canary_7b87f7b9"
    findings = scan(
        f"//registry.example.com/team/:_authToken={canary}\n",
        "npmrc",
        ".npmrc",
    )

    finding = next(f for f in findings if f.pattern_id == "npmrc-auth-token")
    assert canary not in repr(finding)
    assert finding.extracted_dep == "npm-auth-token@registry.example.com"
    assert finding.matched_text == "//registry.example.com/:_authToken=[REDACTED]"
    assert finding.description == (
        "npm registry auth token configured for registry registry.example.com"
    )
    assert finding.sensitive == {
        "redacted": True,
        "kind": "registry-credential",
        "credential_type": "npm-auth-token",
        "host": "registry.example.com",
    }

def test_registry_config_under_test_resources_is_not_reported():
    findings = scan(
        """<configuration>
  <packageSources>
    <add key="tools" value="https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-tools/nuget/v3/index.json" />
  </packageSources>
</configuration>
""",
        "nuget_config",
        "test/Microsoft.ComponentDetection.VerificationTests/resources/nuget/nuspec/NuGet.config",
    )

    assert not any(f.pattern_id == "nuget-custom-feed" for f in findings)


def test_npmrc_under_test_fixtures_is_not_reported():
    findings = scan(
        "registry=https://pkgs.dev.azure.com/org/project/_packaging/feed/npm/registry/\n",
        "npmrc",
        "tests/fixtures/npm/.npmrc",
    )

    assert not any(f.pattern_id == "npmrc-global-registry" for f in findings)


def test_registry_config_in_test_project_without_fixture_directory_is_reported():
    findings = scan(
        """<configuration>
  <packageSources>
    <add key="restsdk" value="https://pkgs.dev.azure.com/mseng/PipelineTools/_packaging/nugetvssprivate/nuget/v3/index.json" />
  </packageSources>
</configuration>
""",
        "nuget_config",
        "src/Test/NuGet.Config",
    )

    assert any(f.pattern_id == "nuget-custom-feed" for f in findings)


def test_nuget_cli_push_custom_source_is_reported():
    findings = scan(
        'dotnet nuget push "./out/*.nupkg" --skip-duplicate '
        "--api-key ${{ secrets.GITHUB_TOKEN }} "
        "--source https://nuget.pkg.github.com/${{ github.repository_owner }}\n"
        "call dotnet nuget push %%f --api-key %~2 --timeout 1200 "
        "--source https://msazure.pkgs.visualstudio.com/_packaging/CRC-VC/nuget/v3/index.json "
        "--skip-duplicate\n",
        "github_action",
        ".github/workflows/release.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "nuget-cli-source-url"
    }
    assert deps == {
        "https://nuget.pkg.github.com/${{ github.repository_owner }}",
        "https://msazure.pkgs.visualstudio.com/_packaging/CRC-VC/nuget/v3/index.json",
    }


def test_nuget_cli_add_custom_source_is_reported():
    findings = scan(
        "dotnet nuget add source "
        "https://pkgs.dev.azure.com/org/project/_packaging/feed/nuget/v3/index.json "
        "--name feed\n",
        "script",
        "setup.sh",
    )

    assert any(
        f.pattern_id == "nuget-cli-source-url"
        and f.extracted_dep == "https://pkgs.dev.azure.com/org/project/_packaging/feed/nuget/v3/index.json"
        for f in findings
    )


def test_dotnet_tool_add_source_url_is_reported_from_folded_yaml():
    feed = "https://pkgs.dev.azure.com/azure-sdk/public/_packaging/azure-sdk-for-net/nuget/v3/index.json"
    findings = scan(
        "run: >\n"
        "  dotnet tool install\n"
        "  Azure.Sdk.Tools.GitHubEventProcessor\n"
        "  --version 1.0.0-dev.20260403.1\n"
        f"  --add-source {feed}\n"
        "  --global\n",
        "ci",
        ".github/workflows/event-processor.yml",
    )

    assert any(
        f.pattern_id == "nuget-cli-source-url"
        and f.extracted_dep == feed
        and f.line_number == 5
        for f in findings
    )


def test_dotnet_tool_add_source_canonical_nuget_is_not_reported():
    findings = scan(
        "dotnet tool install Example.Tool --add-source https://api.nuget.org/v3/index.json\n",
        "ci",
        ".github/workflows/tools.yml",
    )

    assert not any(f.pattern_id == "nuget-cli-source-url" for f in findings)


def test_nuget_cli_canonical_source_is_not_reported():
    findings = scan(
        "dotnet nuget push ./artifacts/*.nupkg "
        "--source https://api.nuget.org/v3/index.json "
        "--api-key $NUGET_API_KEY --skip-duplicate\n"
        "nuget sources add -name nuget.org -source https://www.nuget.org/api/v2\n",
        "github_action",
        ".github/workflows/publish.yml",
    )

    assert not any(f.pattern_id == "nuget-cli-source-url" for f in findings)


def test_pip_config_set_custom_index_is_reported():
    findings = scan(
        "pip config set global.index-url "
        "https://pkgs.dev.azure.com/aiinfra/PublicPackages/_packaging/ORT-Nightly/pypi/simple/\n"
        "pip config set global.extra-index-url https://pypi.org/simple/\n",
        "github_action",
        ".github/workflows/samples-integration-test.yml",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-config-set-index"
    }
    assert deps == {
        "https://pkgs.dev.azure.com/aiinfra/PublicPackages/_packaging/ORT-Nightly/pypi/simple/"
    }


def test_pip_config_set_custom_index_allows_scope_flags():
    findings = scan(
        "pip config --site set global.extra-index-url https://download.pytorch.org/whl/cu121\n"
        "python -m pip config --user set index-url https://download.pytorch.org/whl/cpu\n",
        "script",
        "python/tts/speechT5/setup.sh",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "pip-config-set-index"
    }
    assert deps == {
        "https://download.pytorch.org/whl/cu121",
        "https://download.pytorch.org/whl/cpu",
    }


def test_pip_config_set_scope_flag_canonical_pypi_is_not_reported():
    findings = scan(
        "pip config --site set global.extra-index-url https://pypi.org/simple/\n",
        "script",
        "setup.sh",
    )

    assert not any(f.pattern_id == "pip-config-set-index" for f in findings)


def test_pip_env_index_url_in_dockerfile_is_reported():
    findings = scan(
        "ENV DEBIAN_FRONTEND=noninteractive \\\n"
        "    PIP_NO_CACHE_DIR=1 \\\n"
        "    PIP_EXTRA_INDEX_URL=https://download.pytorch.org/whl/cu121\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "pip-env-index-url"
        and f.extracted_dep == "https://download.pytorch.org/whl/cu121"
        for f in findings
    )


def test_pip_env_index_url_in_workflow_env_is_reported():
    findings = scan(
        "env:\n"
        "  PIP_INDEX_URL: \"https://pkgs.dev.azure.com/org/project/_packaging/feed/pypi/simple\"\n",
        "ci",
        ".github/workflows/ci.yml",
    )

    assert any(
        f.pattern_id == "pip-env-index-url"
        and f.extracted_dep == "https://pkgs.dev.azure.com/org/project/_packaging/feed/pypi/simple"
        for f in findings
    )


def test_pip_env_index_url_powershell_assignment_is_reported():
    findings = scan(
        '$env:PIP_EXTRA_INDEX_URL="https://download.pytorch.org/whl/cpu"\n',
        "script",
        "setup.ps1",
    )

    assert any(
        f.pattern_id == "pip-env-index-url"
        and f.extracted_dep == "https://download.pytorch.org/whl/cpu"
        for f in findings
    )


def test_pip_env_index_url_canonical_pypi_is_not_reported():
    findings = scan(
        "PIP_INDEX_URL=https://pypi.python.org/simple\n"
        "PIP_EXTRA_INDEX_URL: https://pypi.org/simple/\n",
        "ci",
        ".github/workflows/ci.yml",
    )

    assert not any(f.pattern_id == "pip-env-index-url" for f in findings)


def test_npm_and_yarn_config_set_localhost_registry_are_not_reported():
    findings = scan(
        "call npm config set registry http://localhost:4873\n"
        "call yarn config set npmRegistryServer http://localhost:4873\n",
        "script",
        "vnext/Scripts/creaternwapp.cmd",
    )

    assert not any(f.pattern_id in {"npm-config-set-registry", "yarn-config-set-registry"} for f in findings)


def test_npm_and_yarn_config_set_custom_registry_are_reported():
    findings = scan(
        "npm config set registry https://pkgs.dev.azure.com/org/project/_packaging/feed/npm/registry/\n"
        "yarn config set npmRegistryServer https://npm.pkg.github.com\n",
        "script",
        "setup.sh",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id in {"npm-config-set-registry", "yarn-config-set-registry"}
    }
    assert deps == {
        "https://pkgs.dev.azure.com/org/project/_packaging/feed/npm/registry/",
        "https://npm.pkg.github.com",
    }


def test_npm_registry_environment_variable_is_reported():
    findings = scan(
        "env:\n"
        "  npm_config_registry: 'https://pkgs.dev.azure.com/mseng/PipelineTools/_packaging/PipelineTools_PublicPackages/npm/registry/'\n"
        "  npm_config_userconfig: '$(Build.SourcesDirectory)/.npmrc'\n",
        "ci",
        ".pipelines/1es-migration/azure-pipelines.yml",
    )

    assert any(
        f.pattern_id == "npm-env-registry"
        and f.extracted_dep == "https://pkgs.dev.azure.com/mseng/PipelineTools/_packaging/PipelineTools_PublicPackages/npm/registry/"
        for f in findings
    )


def test_npm_task_custom_command_registry_is_reported():
    findings = scan(
        "- task: Npm@1\n"
        "  displayName: 'Install TFX CLI'\n"
        "  inputs:\n"
        "    command: custom\n"
        "    customCommand: 'install -g tfx-cli --registry https://pkgs.dev.azure.com/mseng/PipelineTools/_packaging/PipelineTools_PublicPackages/npm/registry/'\n",
        "ci",
        ".pipelines/1es-migration/azure-pipelines.yml",
    )

    assert any(
        f.pattern_id == "npm-task-custom-command-registry"
        and f.extracted_dep == "https://pkgs.dev.azure.com/mseng/PipelineTools/_packaging/PipelineTools_PublicPackages/npm/registry/"
        for f in findings
    )


def test_npm_env_and_task_custom_command_canonical_registry_are_not_reported():
    findings = scan(
        "NPM_CONFIG_REGISTRY=https://registry.npmjs.org/\n"
        "customCommand: 'install -g eslint --registry https://registry.npmjs.com/'\n",
        "ci",
        ".github/workflows/ci.yml",
    )

    assert not any(
        f.pattern_id in {"npm-env-registry", "npm-task-custom-command-registry"}
        for f in findings
    )


def test_localhost_registry_config_files_are_not_reported():
    for content, file_type, name, pattern_id in (
        ("registry=http://127.0.0.1:4873\n", "npmrc", ".npmrc", "npmrc-global-registry"),
        ('npmRegistryServer: "http://[::1]:4873"\n', "npmrc", ".yarnrc.yml", "yarnrc-npm-registry"),
        ("index-url = http://0.0.0.0:3141/root/pypi/+simple/\n", "pip_conf", "pip.conf", "pip-conf-custom-index"),
    ):
        findings = scan(content, file_type, name)
        assert not any(f.pattern_id == pattern_id for f in findings)


def test_npm_config_set_canonical_registry_is_not_reported():
    findings = scan(
        '"preinstall": "npm config set registry https://registry.npmjs.org/",\n',
        "package_config",
        "package.json",
    )

    assert not any(f.pattern_id == "npm-config-set-registry" for f in findings)


def test_npm_cli_registry_flag_reports_custom_registry_in_package_script():
    registry = (
        "https://pkgs.dev.azure.com/artifacts-public/"
        "23934c1b-a3b5-4b70-9dd3-d1bef4cc72a0/_packaging/AzureArtifacts/npm/registry/"
    )
    findings = scan(
        f'"installCredProvider": "npm install --global @microsoft/artifacts-npm-credprovider '
        f'--registry {registry}",\n',
        "package_config",
        "package.json",
    )

    assert any(
        f.pattern_id == "npm-cli-registry"
        and f.extracted_dep == registry
        for f in findings
    )


def test_npm_cli_registry_flag_supports_equals_form():
    findings = scan(
        "pnpm add @scope/tool --registry=https://npm.pkg.github.com\n",
        "ci",
        ".github/workflows/ci.yml",
    )

    assert any(
        f.pattern_id == "npm-cli-registry"
        and f.extracted_dep == "https://npm.pkg.github.com"
        for f in findings
    )


def test_npm_cli_registry_flag_ignores_canonical_registry():
    findings = scan(
        "npm install --no-save node-gyp --registry https://registry.npmjs.org/\n"
        "yarn add left-pad --registry=https://registry.npmjs.com\n",
        "ci",
        ".github/workflows/samples-integration-test.yml",
    )

    assert not any(f.pattern_id == "npm-cli-registry" for f in findings)


def test_npm_cli_registry_flag_resolves_powershell_variable():
    registry = "https://pkgs.dev.azure.com/azure-sdk/public/_packaging/azure-sdk-for-js@Local/npm/registry/"
    findings = scan(
        f'$NpmDevopsFeedRegistry = "{registry}"\n'
        "npm install $apiviewParser --registry $NpmDevopsFeedRegistry\n",
        "script",
        "eng/emitters/scripts/Generate-APIView-CodeFile.ps1",
    )

    assert any(
        f.pattern_id == "npm-cli-registry"
        and f.extracted_dep == registry
        and f.line_number == 2
        for f in findings
    )


def test_npm_cli_registry_flag_resolves_powershell_env_variable():
    registry = "https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public-npm/npm/registry/"
    findings = scan(
        f'$env:NPM_REGISTRY = "{registry}"\n'
        'npm install --global --force --registry "$env:NPM_REGISTRY" "corepack@$CorepackVersion"\n',
        "script",
        "extension/build.ps1",
    )

    assert any(
        f.pattern_id == "npm-cli-registry"
        and f.extracted_dep == registry
        and f.line_number == 2
        for f in findings
    )


def test_npm_cli_registry_variable_is_ignored_when_not_used_by_registry_flag():
    findings = scan(
        '$env:NPM_REGISTRY = "https://pkgs.dev.azure.com/org/project/_packaging/feed/npm/registry/"\n'
        "npm install @scope/tool\n",
        "script",
        "build.ps1",
    )

    assert not any(f.pattern_id == "npm-cli-registry" for f in findings)


def test_sample_registry_config_is_reported():
    findings = scan(
        """<configuration>
  <packageSources>
    <add key="dotnet-public" value="https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json" />
  </packageSources>
</configuration>
""",
        "nuget_config",
        "samples/public/NuGet.config",
    )

    assert any(f.pattern_id == "nuget-custom-feed" for f in findings)


def test_azure_pipelines_task_test_npmrc_is_not_active_registry_config():
    content = "registry=https://pkgs.dev.azure.com/mseng/PipelineTools/_packaging/Public/npm/registry/\n"

    for name in (
        "Tasks/NpmAuthenticateV0/Tests/.npmrc",
        "_generated/NpmAuthenticateV0/Tests/.npmrc",
    ):
        findings = scan(content, "npmrc", name)
        assert not any(f.pattern_id == "npmrc-global-registry" for f in findings)


def test_azure_pipelines_task_npmrc_outside_tests_is_reported():
    findings = scan(
        "registry=https://pkgs.dev.azure.com/mseng/PipelineTools/_packaging/Public/npm/registry/\n",
        "npmrc",
        "Tasks/NpmAuthenticateV0/.npmrc",
    )

    assert any(f.pattern_id == "npmrc-global-registry" for f in findings)


def test_register_psrepository_url_source_is_reported():
    findings = scan(
        "Register-PSRepository -Name Internal "
        "-SourceLocation https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v2 "
        "-InstallationPolicy Trusted\n",
        "script",
        "setup.ps1",
    )

    assert any(
        f.pattern_id == "powershell-repository-source"
        and f.extracted_dep == "https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v2"
        for f in findings
    )


def test_register_psrepository_source_variable_in_shell_command_is_reported():
    findings = scan(
        "pwsh -NoProfile -Command "
        "'Register-PSRepository -Name $env:PSGALLERY_REPO "
        "-SourceLocation $env:PSGALLERY_SOURCE -InstallationPolicy Trusted'\n",
        "script",
        ".devcontainer/scripts/on-create.sh",
    )

    assert any(
        f.pattern_id == "powershell-repository-source"
        and f.extracted_dep == "$env:PSGALLERY_SOURCE"
        for f in findings
    )


def test_register_psrepository_local_sources_are_not_reported():
    findings = scan(
        "Register-PSRepository -Name Local -SourceLocation out/repo -InstallationPolicy Trusted\n"
        "Register-PSRepository -Name $RepoName -SourceLocation $RepoPath -InstallationPolicy Trusted\n"
        "Register-PSRepository -Name OutPath -SourceLocation $nugetPath -PublishLocation $nugetPath\n"
        'Write-Host "Register-PSRepository -Name Internal -SourceLocation https://example.com/feed"\n',
        "script",
        "LocalRepoFunctions.ps1",
    )

    assert not any(f.pattern_id == "powershell-repository-source" for f in findings)


def test_canonical_yarn_npm_registry_is_not_reported():
    findings = scan(
        'npmRegistryServer: "https://registry.npmjs.org"\n',
        "npmrc",
        ".yarnrc.yml",
    )

    assert not any(f.pattern_id.startswith("yarnrc-npm-") for f in findings)


def test_nonstandard_yarn_npm_registry_is_reported_once_without_quote():
    findings = scan(
        'npmRegistryServer: "https://pkgs.dev.azure.com/org/project/_packaging/feed/npm/registry/"\n',
        "npmrc",
        ".yarnrc.yml",
    )

    yarn_findings = [f for f in findings if f.pattern_id.startswith("yarnrc-npm-")]
    assert len(yarn_findings) == 1
    assert yarn_findings[0].pattern_id == "yarnrc-npm-registry"
    assert yarn_findings[0].extracted_dep == "https://pkgs.dev.azure.com/org/project/_packaging/feed/npm/registry/"


def test_detects_downloaded_apt_signing_key():
    findings = scan(
        "RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg "
        "| gpg --dearmor | tee /etc/apt/keyrings/yarn-archive-keyring.gpg > /dev/null\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://dl.yarnpkg.com/debian/pubkey.gpg"
        for f in findings
    )


def test_detects_downloaded_apt_signing_key_to_usr_share_keyrings():
    findings = scan(
        "RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc "
        "| gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://packages.microsoft.com/keys/microsoft.asc"
        for f in findings
    )


def test_detects_multiline_downloaded_apt_signing_key_to_usr_share_keyrings():
    findings = scan(
        "RUN apt-get install -y gnupg \\\n"
        " && curl -sL https://packages.microsoft.com/keys/microsoft.asc \\\n"
        "      | gpg --dearmor \\\n"
        "      > /usr/share/keyrings/microsoft-archive-keyring.gpg\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://packages.microsoft.com/keys/microsoft.asc"
        and f.line_number == 2
        for f in findings
    )


def test_detects_multiline_downloaded_apt_signing_key_piped_to_tee():
    findings = scan(
        "curl -sLS https://packages.microsoft.com/keys/microsoft.asc \\\n"
        "  | gpg --dearmor \\\n"
        "  | sudo tee /etc/apt/keyrings/microsoft.gpg >/dev/null\n",
        "ci",
        "workflow.yml",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://packages.microsoft.com/keys/microsoft.asc"
        and f.line_number == 1
        for f in findings
    )


def test_detects_downloaded_apt_signing_key_piped_to_tee():
    findings = scan(
        "RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key "
        "| tee /etc/apt/keyrings/nodesource.gpg > /dev/null\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
        for f in findings
    )


def test_detects_multiline_downloaded_apt_signing_key_piped_to_tee_without_gpg():
    findings = scan(
        "RUN apt-get install -y gnupg \\\n"
        "    && mkdir -p /etc/apt/keyrings \\\n"
        "    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \\\n"
        "        | tee /etc/apt/keyrings/nodesource.gpg > /dev/null\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
        and f.line_number == 3
        for f in findings
    )


def test_detects_downloaded_apt_signing_key_piped_to_apt_key():
    findings = scan(
        "wget -O - http://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -\n",
        "script",
        "setup.sh",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "http://apt.llvm.org/llvm-snapshot.gpg.key"
        for f in findings
    )


def test_detects_downloaded_apt_signing_key_dynamic_url_piped_to_wrapped_apt_key():
    findings = scan(
        "curl -fsSL https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]')/gpg "
        "| (OUT=$(apt-key add - 2>&1) || echo $OUT)\n",
        "script",
        "docker-debian.sh",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]')/gpg"
        for f in findings
    )


def test_detects_downloaded_apt_signing_key_piped_to_wrapped_apt_key():
    findings = scan(
        "curl -fsSL https://download.docker.com/linux/debian/gpg "
        "| (OUT=$(apt-key add - 2>&1) || echo $OUT)\n",
        "script",
        "docker-debian.sh",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://download.docker.com/linux/debian/gpg"
        for f in findings
    )


def test_detects_variable_downloaded_apt_signing_key_to_keyring():
    findings = scan(
        'curl -fsSL "${NEXUS_PROXY_URL}"/repository/microsoft-keys/microsoft.asc '
        "| sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/microsoft.gpg\n",
        "script",
        "get_apt_keys.sh",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "${NEXUS_PROXY_URL}/repository/microsoft-keys/microsoft.asc"
        for f in findings
    )


def test_detects_downloaded_apt_signing_key_direct_to_keyring():
    findings = scan(
        "sudo curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key "
        "-o /usr/share/keyrings/ros-archive-keyring.gpg\n",
        "script",
        "install_ros2_deps.sh",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://raw.githubusercontent.com/ros/rosdistro/master/ros.key"
        for f in findings
    )


def test_detects_downloaded_apt_signing_key_installed_from_temp_file():
    findings = scan(
        "wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg\n"
        "sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg\n",
        "script",
        "bootstrap-linux.sh",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://packages.microsoft.com/keys/microsoft.asc"
        for f in findings
    )


def test_detects_downloaded_apt_signing_key_temp_file_dearmored_to_keyring():
    findings = scan(
        "curl -fsSL -o /tmp/microsoft.asc https://packages.microsoft.com/keys/microsoft.asc\n"
        "echo \"$MICROSOFT_GPG_SHA256  /tmp/microsoft.asc\" | sha256sum -c --quiet -\n"
        "sudo gpg --dearmor --batch --yes -o /etc/apt/keyrings/microsoft.gpg < /tmp/microsoft.asc\n",
        "script",
        "install-dev-deps.sh",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://packages.microsoft.com/keys/microsoft.asc"
        for f in findings
    )


def test_detects_apt_key_adv_fetch_keys_url():
    findings = scan(
        'apt-key adv --fetch-keys "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/7fa2af80.pub"\n',
        "script",
        "provision-image.sh",
    )

    assert any(
        f.pattern_id == "apt-signing-key-download"
        and f.extracted_dep == "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/7fa2af80.pub"
        for f in findings
    )


def test_detects_apt_key_adv_keyserver_recv_key():
    findings = scan(
        "sudo apt-key adv --keyserver 'hkp://keyserver.ubuntu.com:80' "
        "--recv-key C1CF6E31E6BADE8868B172B4F42ED6FBAB17C654\n",
        "script",
        "install_ros_deps.sh",
    )

    assert any(
        f.pattern_id == "apt-keyserver-key-import"
        and f.extracted_dep == "hkp://keyserver.ubuntu.com:80#C1CF6E31E6BADE8868B172B4F42ED6FBAB17C654"
        for f in findings
    )


def test_detects_chrooted_apt_key_adv_keyserver_recv_keys():
    findings = scan(
        "chroot /crossrootfs/x64 apt-key adv --keyserver keyserver.ubuntu.com "
        "--recv-keys 60C317803A41BA51845E371A1E9377A2BA9EF27F && \\\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "apt-keyserver-key-import"
        and f.extracted_dep == "keyserver.ubuntu.com#60C317803A41BA51845E371A1E9377A2BA9EF27F"
        for f in findings
    )


def test_apt_key_adv_keyserver_ignores_agent_instruction_markdown():
    findings = scan(
        "Run `apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 60C317803A41BA51845E371A1E9377A2BA9EF27F` only in old images.\n",
        "agent_instruction",
        "setup-dev-env.prompt.md",
    )

    assert not any(f.pattern_id == "apt-keyserver-key-import" for f in findings)


def test_detects_downloaded_apt_repo_package_installed_with_dpkg():
    findings = scan(
        "wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb\n"
        "sudo dpkg -i packages-microsoft-prod.deb\n",
        "script",
        "bootstrap-linux.sh",
    )

    assert any(
        f.pattern_id == "apt-repo-package-download"
        and f.extracted_dep == "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb"
        for f in findings
    )
    assert not any(f.pattern_id == "apt-signing-key-download" for f in findings)


def test_detects_dynamic_downloaded_apt_repo_package_installed_with_dpkg():
    findings = scan(
        "curl -fsSL -O https://packages.microsoft.com/config/ubuntu/$(grep VERSION_ID /etc/os-release | cut -d '\"' -f 2)/packages-microsoft-prod.deb\n"
        "sudo dpkg -i packages-microsoft-prod.deb\n",
        "ci",
        "workflow.yml",
    )

    assert any(
        f.pattern_id == "apt-repo-package-download"
        and f.extracted_dep
        == "https://packages.microsoft.com/config/ubuntu/$(grep VERSION_ID /etc/os-release | cut -d '\"' -f 2)/packages-microsoft-prod.deb"
        for f in findings
    )
    assert not any(f.pattern_id == "apt-signing-key-download" for f in findings)


def test_detects_dynamic_apt_repo_package_installed_with_dpkg_wrapper():
    findings = scan(
        'curl -sSL -O "https://packages.microsoft.com/config/${DISTRO}/${VERSION}/packages-microsoft-prod.deb"\n'
        "dpkg_install packages-microsoft-prod.deb\n",
        "script",
        "install-dev-deps.sh",
    )

    assert any(
        f.pattern_id == "apt-repo-package-download"
        and f.extracted_dep == "https://packages.microsoft.com/config/${DISTRO}/${VERSION}/packages-microsoft-prod.deb"
        for f in findings
    )
    assert not any(f.pattern_id == "apt-signing-key-download" for f in findings)


def test_detects_dockerfile_add_apt_repo_package_installed_with_dpkg():
    findings = scan(
        "ADD https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb /packages-microsoft-prod.deb\n"
        "RUN <<END_OF_SCRIPT bash\n"
        "set -e\n"
        "dpkg -i packages-microsoft-prod.deb\n"
        "END_OF_SCRIPT\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "apt-repo-package-download"
        and f.extracted_dep == "https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb"
        for f in findings
    )
    assert not any(f.pattern_id == "apt-signing-key-download" for f in findings)


def test_detects_downloaded_apk_signing_key_to_apk_keys():
    findings = scan(
        "RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub "
        "https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "apk-signing-key-download"
        and f.extracted_dep == "https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub"
        for f in findings
    )


def test_detects_downloaded_apk_signing_key_url_before_output():
    findings = scan(
        "curl -fsSL https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub "
        "-o /etc/apk/keys/sgerrand.rsa.pub\n",
        "dockerfile",
        "Dockerfile",
    )

    assert any(
        f.pattern_id == "apk-signing-key-download"
        and f.extracted_dep == "https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub"
        for f in findings
    )


def test_detects_yum_repo_config_download_to_repo_dir():
    findings = scan(
        "wget -P /etc/yum.repos.d/ https://packages.efficios.com/repo.files/EfficiOS-RHEL7-x86-64.repo\n",
        "script",
        "installdependencies.sh",
    )

    assert any(
        f.pattern_id == "yum-repo-config-download"
        and f.extracted_dep == "https://packages.efficios.com/repo.files/EfficiOS-RHEL7-x86-64.repo"
        for f in findings
    )


def test_detects_yum_repo_config_download_redirected_to_repo_dir():
    findings = scan(
        "curl -s https://packages.microsoft.com/config/rhel/7/prod.repo > /etc/yum.repos.d/mssql-release.repo\n",
        "script",
        "setup_env_unix.sh",
    )

    assert any(
        f.pattern_id == "yum-repo-config-download"
        and f.extracted_dep == "https://packages.microsoft.com/config/rhel/7/prod.repo"
        for f in findings
    )


def test_detects_dnf_config_manager_add_repo_as_registry_config():
    findings = scan(
        "sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo\n",
        "script",
        "setup-devcontainer.sh",
    )

    assert any(
        f.pattern_id == "yum-repo-config-add"
        and f.extracted_dep == "https://download.docker.com/linux/fedora/docker-ce.repo"
        for f in findings
    )


def test_detects_inline_yum_repo_file_write_baseurl():
    findings = scan(
        "sudo sh -c 'echo -e \"[code]\\nname=Visual Studio Code\\n"
        "baseurl=https://packages.microsoft.com/yumrepos/vscode\\n"
        "enabled=1\\ngpgcheck=1\\n"
        "gpgkey=https://packages.microsoft.com/keys/microsoft.asc\" > /etc/yum.repos.d/vscode.repo'\n",
        "script",
        "setup-devcontainer.sh",
    )

    assert any(
        f.pattern_id == "yum-repo-config-write"
        and f.extracted_dep == "https://packages.microsoft.com/yumrepos/vscode"
        for f in findings
    )


def test_detects_multiline_yum_repo_file_write_baseurl():
    findings = scan(
        "echo -e \"[azure-cli]\\n"
        "name=Azure CLI\\n"
        "baseurl=https://packages.microsoft.com/yumrepos/azure-cli\\n"
        "enabled=1\\n"
        "gpgcheck=1\\n"
        "gpgkey=https://packages.microsoft.com/keys/microsoft.asc\" | sudo tee /etc/yum.repos.d/azure-cli.repo\n",
        "script",
        "quick-container.sh",
    )

    assert any(
        f.pattern_id == "yum-repo-config-write"
        and f.extracted_dep == "https://packages.microsoft.com/yumrepos/azure-cli"
        for f in findings
    )


def test_yum_repo_config_write_ignores_mirror_sed_edit():
    findings = scan(
        "sudo sed -i 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' "
        "/etc/yum.repos.d/CentOS-*.repo\n",
        "script",
        "pipeline-test.sh",
    )

    assert not any(f.pattern_id == "yum-repo-config-write" for f in findings)


def test_detects_zypper_repo_config_add():
    findings = scan(
        "zypper -n ar https://packages.microsoft.com/config/sles/12/prod.repo\n"
        "zypper --gpg-auto-import-keys refresh\n",
        "script",
        "setup_env_unix.sh",
    )

    assert any(
        f.pattern_id == "zypper-repo-config-add"
        and f.extracted_dep == "https://packages.microsoft.com/config/sles/12/prod.repo"
        for f in findings
    )


def test_detects_zypper_addrepo_config_url():
    findings = scan(
        "sudo zypper --non-interactive addrepo -f https://packages.example.com/sles/prod.repo example-prod\n",
        "script",
        "install-sles.sh",
    )

    assert any(
        f.pattern_id == "zypper-repo-config-add"
        and f.extracted_dep == "https://packages.example.com/sles/prod.repo"
        for f in findings
    )


def test_zypper_repo_config_add_ignores_agent_instruction_markdown():
    findings = scan(
        "For SUSE, run `zypper -n ar https://packages.microsoft.com/config/sles/12/prod.repo`.\n",
        "agent_instruction",
        "Linux-mac-install.md",
    )

    assert not any(f.pattern_id == "zypper-repo-config-add" for f in findings)


def test_detects_rpm_signing_key_import():
    findings = scan(
        "rpmkeys --import https://packages.efficios.com/rhel/repo.key\n",
        "script",
        "installdependencies.sh",
    )

    assert any(
        f.pattern_id == "rpm-signing-key-import"
        and f.extracted_dep == "https://packages.efficios.com/rhel/repo.key"
        for f in findings
    )


def test_detects_debsig_signing_key_download():
    findings = scan(
        "curl -sS https://downloads.1password.com/linux/keys/1password.asc "
        "| sudo gpg --dearmor --output /usr/share/debsig/keyrings/AC2D62742012EA22/debsig.gpg\n",
        "script",
        "1PasswordInstall.sh",
    )

    assert any(
        f.pattern_id == "debsig-signing-key-download"
        and f.extracted_dep == "https://downloads.1password.com/linux/keys/1password.asc"
        for f in findings
    )
