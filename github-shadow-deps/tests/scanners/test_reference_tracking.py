"""Tests for ReferenceTrackingScanner (script/file reference detection)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Severity
from github_inventory.scanners.reference_tracking import ReferenceTrackingScanner


def scan(content: str, file_type: str = "ci", rel_path: str | None = None):
    scanner = ReferenceTrackingScanner(Config())
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(content)
        p = Path(f.name)
    target = FileTarget(path=p, rel_path=rel_path or p.name, file_type=file_type)
    return scanner.scan_file(target)


class TestGitHubActionsReferences:
    def test_detects_run_script_with_dot_slash(self):
        findings = scan("      - run: ./scripts/deploy.sh\n")
        assert len(findings) == 1
        assert findings[0].pattern_id == "github-action-run-script"
        assert findings[0].category == Category.SCRIPT_REFERENCE
        assert findings[0].severity == Severity.MEDIUM
        assert "deploy.sh" in findings[0].extracted_dep

    def test_detects_run_script_with_bash(self):
        findings = scan("      - run: bash scripts/test.sh\n")
        assert any(f.pattern_id == "github-action-run-script" for f in findings)
        assert any("test.sh" in f.extracted_dep for f in findings)

    def test_detects_run_script_with_sh(self):
        findings = scan("      - run: sh build/build.sh\n")
        assert any(f.pattern_id == "github-action-run-script" for f in findings)

    def test_ignores_commented_run(self):
        findings = scan("      # - run: ./scripts/deploy.sh\n")
        assert findings == []

    def test_ignores_run_word_inside_script_output_message(self):
        findings = scan(
            "      - name: Validate generated tool\n"
            "        shell: pwsh\n"
            "        run: |\n"
            '          Write-Host "::error::Run: ./scripts/build-tools.ps1, then commit the refreshed exe"\n'
        )

        assert not any(
            f.pattern_id == "github-action-run-script"
            and f.extracted_dep == "./scripts/build-tools.ps1"
            for f in findings
        )

    def test_detects_powershell_script(self):
        findings = scan("      - run: ./scripts/deploy.ps1\n")
        assert any("deploy.ps1" in f.extracted_dep for f in findings)

    def test_dedupes_repeated_same_file_scripts(self):
        findings = scan(
            "      - run: tools/check.ps1 -Config Debug\n"
            "      - run: tools/check.ps1 -Config Release\n"
            "      - run: tools/test.ps1\n"
        )

        deps = [
            f.extracted_dep for f in findings
            if f.pattern_id == "github-action-run-script"
        ]
        assert deps == ["tools/check.ps1", "tools/test.ps1"]


class TestDockerfileReferences:
    def test_detects_copy_script(self):
        findings = scan("COPY scripts/setup.sh /app/setup.sh\n", file_type="dockerfile")
        assert any(f.pattern_id == "dockerfile-copy-script" for f in findings)
        assert any("setup.sh" in f.extracted_dep for f in findings)

    def test_detects_add_script(self):
        findings = scan("ADD scripts/init.sh /etc/init.sh\n", file_type="dockerfile")
        assert any(f.pattern_id == "dockerfile-copy-script" for f in findings)

    def test_detects_python_script(self):
        findings = scan("COPY build.py /app/build.py\n", file_type="dockerfile")
        assert any("build.py" in f.extracted_dep for f in findings)

    def test_detects_javascript_file(self):
        findings = scan("COPY server.js /app/server.js\n", file_type="dockerfile")
        assert any("server.js" in f.extracted_dep for f in findings)

    def test_ignores_copy_script_in_test_resource_dockerfile(self):
        findings = scan(
            "COPY hijack.sh /hijack.sh\n",
            file_type="dockerfile",
            rel_path="test/Microsoft.ComponentDetection.VerificationTests/resources/dockerFiles/python.dockerfile",
        )

        assert not any(f.pattern_id == "dockerfile-copy-script" for f in findings)


class TestDockerComposeReferences:
    def test_detects_build_dockerfile_reference(self):
        findings = scan("    build: ./services/api/Dockerfile\n", file_type="dockerfile")
        assert any(f.pattern_id == "compose-build-reference" for f in findings)
        assert any("Dockerfile" in f.extracted_dep for f in findings)

    def test_detects_build_context_reference(self):
        findings = scan("    build: ./backend\n", file_type="dockerfile")
        assert any(f.pattern_id == "compose-build-reference" for f in findings)

    def test_detects_volume_script_mount(self):
        findings = scan("    volumes:\n      - ./scripts/entrypoint.sh:/entrypoint.sh\n", file_type="dockerfile")
        assert any(f.pattern_id == "docker-compose-volume-script" for f in findings)
        assert any("entrypoint.sh" in f.extracted_dep for f in findings)


class TestMakefileReferences:
    def test_detects_script_invocation(self):
        findings = scan("build:\n\t./scripts/build.sh\n", file_type="build")
        assert any(f.pattern_id == "makefile-script-reference" for f in findings)
        assert any("build.sh" in f.extracted_dep for f in findings)

    def test_detects_bash_invocation(self):
        findings = scan("test:\n\tbash scripts/test.sh\n", file_type="build")
        assert any(f.pattern_id == "makefile-script-reference" for f in findings)

    def test_strips_makefile_command_prefix_from_script_reference(self):
        findings = scan("test:\n\t@./scripts/harness/test.sh\n", file_type="build")

        assert any(
            f.pattern_id == "makefile-script-reference"
            and f.extracted_dep == "./scripts/harness/test.sh"
            for f in findings
        )
        assert not any(
            f.pattern_id == "makefile-script-reference"
            and f.extracted_dep.startswith("@")
            for f in findings
        )

    def test_ignores_script_target_definition(self):
        findings = scan("$(DST_DIR)/ctw.sh: $(DST_DIR)\n", file_type="build")
        assert not any(f.pattern_id == "makefile-script-reference" for f in findings)

    def test_ignores_url_ending_sh_in_build_file(self):
        findings = scan(
            "add_custom_command(\n"
            "  COMMAND git clone --depth 1\n"
            "    https://github.com/drwetter/testssl.sh\n"
            ")\n",
            file_type="build",
        )

        assert not any(
            f.pattern_id == "makefile-script-reference"
            and f.extracted_dep == "https://github.com/drwetter/testssl.sh"
            for f in findings
        )

    def test_ignores_cmake_script_glob(self):
        findings = scan(
            "file(GLOB\n"
            "    RES_FILES\n"
            '    "${CMAKE_CURRENT_SOURCE_DIR}/*.sh"\n'
            ")\n",
            file_type="build",
        )

        assert not any(f.pattern_id == "makefile-script-reference" for f in findings)

    def test_ignores_cmake_configure_file_script_reference(self):
        findings = scan(
            "configure_file(run_mpi_test.sh.in run_mpi_test.sh)\n",
            file_type="build",
            rel_path="test/CMakeLists.txt",
        )

        assert not any(f.pattern_id == "makefile-script-reference" for f in findings)

    def test_ignores_gradle_plugin_id_containing_sh_prefix(self):
        findings = scan(
            'plugins {\n    id("ai.shadow-conventions")\n}\n',
            file_type="build",
            rel_path="agent/build.gradle.kts",
        )

        assert not any(f.pattern_id == "makefile-script-reference" for f in findings)


class TestPackageJsonReferences:
    def test_detects_preinstall_script(self):
        findings = scan('"preinstall": "./scripts/preinstall.sh"', file_type="package_config")
        assert any(f.pattern_id == "npm-script-file-reference" for f in findings)
        assert any("preinstall.sh" in f.extracted_dep for f in findings)

    def test_ignores_local_node_build_script(self):
        findings = scan('"build": "node build/build.js"', file_type="package_config")
        assert not any(f.pattern_id == "npm-script-file-reference" for f in findings)

    def test_ignores_local_node_start_script(self):
        findings = scan('"start": "node server.js"', file_type="package_config")
        assert not any(f.pattern_id == "npm-script-file-reference" for f in findings)

    def test_ignores_local_mocha_test_script(self):
        findings = scan('"test": "mocha L0.js"', file_type="package_config")
        assert not any(f.pattern_id == "npm-script-file-reference" for f in findings)

    def test_ignores_local_node_script_after_build_step(self):
        findings = scan(
            '"test": "tsc -b && node dist/mcpValidationTest.js"',
            file_type="package_config",
        )
        assert not any(f.pattern_id == "npm-script-file-reference" for f in findings)

    def test_ignores_local_tool_config_build_script(self):
        findings = scan(
            '"build": "webpack --mode production --config webpack.config.js"',
            file_type="package_config",
        )
        assert not any(f.pattern_id == "npm-script-file-reference" for f in findings)

    def test_ignores_local_pm2_start_script(self):
        findings = scan('"start": "pm2 start -n service dist/index.js"', file_type="package_config")
        assert not any(f.pattern_id == "npm-script-file-reference" for f in findings)

    def test_ignores_local_test_glob_script(self):
        findings = scan(
            '"test": "cross-env NODE_ENV=test mocha -R spec --exit lib/*.test.js"',
            file_type="package_config",
        )
        assert not any(f.pattern_id == "npm-script-file-reference" for f in findings)

    def test_ignores_local_build_copy_script(self):
        findings = scan(
            '"build": "mkdir -p build && cp server.js build/server.js"',
            file_type="package_config",
        )
        assert not any(f.pattern_id == "npm-script-file-reference" for f in findings)

    def test_ignores_local_build_chmod_script(self):
        findings = scan('"build": "tsc && shx chmod +x dist/*.js"', file_type="package_config")
        assert not any(f.pattern_id == "npm-script-file-reference" for f in findings)

    def test_detects_postinstall_script(self):
        findings = scan('"postinstall": "./setup.sh"', file_type="package_config")
        assert any("setup.sh" in f.extracted_dep for f in findings)

    def test_detects_preinstall_node_script(self):
        findings = scan('"preinstall": "node scripts/preinstall.js"', file_type="package_config")
        assert any("preinstall.js" in f.extracted_dep for f in findings)

    def test_detects_deploy_shell_script(self):
        findings = scan('"deploy": "bash scripts/deploy.sh"', file_type="package_config")
        assert any(
            f.pattern_id == "npm-script-file-reference"
            and f.extracted_dep == "scripts/deploy.sh"
            for f in findings
        )


class TestKubernetesReferences:
    def test_detects_configmap_embedded_script(self):
        content = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: init-scripts
data:
  setup.sh: |
    #!/bin/bash
    curl -fsSL https://get.docker.com | bash
"""
        findings = scan(content, file_type="k8s")
        embedded = [f for f in findings if f.pattern_id == "k8s-configmap-embedded-script"]
        assert len(embedded) >= 1
        assert any(f.severity == Severity.HIGH for f in embedded)
        assert any("curl" in f.extracted_dep.lower() for f in embedded)

    def test_detects_command_array_script(self):
        findings = scan('        command: ["/scripts/init.sh"]\n', file_type="k8s")
        assert any(f.pattern_id == "k8s-command-script" for f in findings)
        assert any("init.sh" in f.extracted_dep for f in findings)


class TestFixtureScan:
    def test_scans_github_actions_fixture(self):
        fixture = (
            Path(__file__).parent.parent
            / "fixtures"
            / ".github"
            / "workflows"
            / "github_actions.yml"
        )
        if not fixture.exists():
            pytest.skip("Fixture not found")
        scanner = ReferenceTrackingScanner(Config())
        target = FileTarget(path=fixture, rel_path="github_actions.yml", file_type="ci")
        findings = scanner.scan_file(target)
        # Should detect the reference to ./scripts/deploy.sh
        ref_findings = [f for f in findings if f.category == Category.SCRIPT_REFERENCE]
        assert len(ref_findings) >= 1
        assert any("deploy.sh" in f.extracted_dep for f in ref_findings)

    def test_scans_dockerfile_fixture(self):
        fixture = Path(__file__).parent.parent / "fixtures" / "dockerfiles" / "Dockerfile"
        if not fixture.exists():
            pytest.skip("Fixture not found")
        scanner = ReferenceTrackingScanner(Config())
        target = FileTarget(path=fixture, rel_path="Dockerfile", file_type="dockerfile")
        findings = scanner.scan_file(target)
        # Should detect COPY scripts/setup.sh
        copy_findings = [f for f in findings if f.pattern_id == "dockerfile-copy-script"]
        assert len(copy_findings) >= 1
        assert any("setup.sh" in f.extracted_dep for f in copy_findings)
