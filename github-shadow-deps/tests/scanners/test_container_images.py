"""Tests for ContainerImageScanner."""
from __future__ import annotations

import tempfile
from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Severity
from github_inventory.scanners.container_images import ContainerImageScanner


def scan(content: str, file_type: str = "dockerfile", name: str | None = None):
    scanner = ContainerImageScanner(Config())
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / (name or "test.yml")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        target = FileTarget(path=p, rel_path=name or p.name, file_type=file_type)
        return scanner.scan_file_content(target, content, content.splitlines())


def scan_rel(content: str, rel_path: str, file_type: str = "dockerfile"):
    scanner = ContainerImageScanner(Config())
    target = FileTarget(path=Path(rel_path), rel_path=rel_path, file_type=file_type)
    return scanner.scan_file_content(target, content, content.splitlines())


def test_flags_from_latest():
    findings = scan("FROM ubuntu:latest\n")
    assert any(f.pattern_id == "unpinned-dockerfile-from" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_flags_from_main():
    findings = scan("FROM node:main\n")
    assert any(f.pattern_id == "unpinned-dockerfile-from" for f in findings)


def test_mutable_dockerfile_from_reports_full_tag_suffix():
    findings = scan("FROM fedirz/faster-whisper-server:latest-cuda\n")

    deps = {f.extracted_dep for f in findings if f.pattern_id == "unpinned-dockerfile-from"}
    assert "fedirz/faster-whisper-server:latest-cuda" in deps
    assert "fedirz/faster-whisper-server:latest" not in deps


def test_flags_from_no_tag():
    findings = scan("FROM python\n")
    assert any(f.pattern_id == "dockerfile-from-no-tag" for f in findings)


def test_does_not_flag_from_with_version():
    findings = scan("FROM node:20.0.0\n")
    # Version-tagged image should NOT be flagged for mutable tag
    mutable_findings = [f for f in findings if f.pattern_id == "unpinned-dockerfile-from"]
    assert mutable_findings == []


def test_non_standard_registry_keeps_variable_tag_suffix():
    findings = scan("FROM nvcr.io/nvidia/cuda:${CUDA_VERSION}-devel-${OS}\n")

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "non-standard-registry"
    }
    assert deps == {"nvcr.io/nvidia/cuda:${CUDA_VERSION}-devel-${OS}"}


def test_does_not_flag_scratch():
    findings = scan("FROM scratch\n")
    no_tag_findings = [f for f in findings if f.pattern_id == "dockerfile-from-no-tag"]
    assert no_tag_findings == []


def test_does_not_flag_multistage_alias_from():
    findings = scan("FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base\nFROM base\n")
    no_tag_findings = [f for f in findings if f.pattern_id == "dockerfile-from-no-tag"]
    assert no_tag_findings == []


def test_does_not_flag_arbitrary_multistage_alias_from():
    findings = scan(
        "FROM rust:1.93-bookworm AS chef\n"
        "FROM chef AS planner\n"
        "FROM chef AS builder\n"
        "FROM debian\n"
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "dockerfile-from-no-tag"
    }
    assert "chef" not in deps
    assert "debian" in deps


def test_dockerfile_from_no_tag_ignores_repo_local_sibling_dockerfile_base(tmp_path):
    docker_dir = tmp_path / "tests" / "Shared" / "Docker"
    docker_dir.mkdir(parents=True)
    (docker_dir / "Dockerfile.e2e-polyglot-base").write_text(
        "FROM mcr.microsoft.com/mirror/docker/library/ubuntu:24.04\n"
    )
    dockerfile = docker_dir / "Dockerfile.e2e-polyglot-java"
    content = "FROM aspire-e2e-polyglot-base\nFROM alpine\n"
    dockerfile.write_text(content)

    scanner = ContainerImageScanner(Config())
    target = FileTarget(
        path=dockerfile,
        rel_path="tests/Shared/Docker/Dockerfile.e2e-polyglot-java",
        file_type="dockerfile",
    )
    findings = scanner.scan_file_content(target, content, content.splitlines())

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "dockerfile-from-no-tag"
    }
    assert "aspire-e2e-polyglot-base" not in deps
    assert "alpine" in deps


def test_flags_k8s_image_latest():
    findings = scan("        image: myapp:latest\n", file_type="k8s")
    assert any(f.pattern_id == "k8s-mutable-image-tag" for f in findings)


def test_mutable_k8s_image_reports_full_tag_suffix():
    findings = scan("        image: fedirz/faster-whisper-server:latest-cuda\n", file_type="k8s")

    deps = {f.extracted_dep for f in findings if f.pattern_id == "k8s-mutable-image-tag"}
    assert "fedirz/faster-whisper-server:latest-cuda" in deps
    assert "fedirz/faster-whisper-server:latest" not in deps


def test_flags_structured_helm_repository_tag_mutable_image():
    findings = scan(
        "worker:\n"
        "  image:\n"
        "    repository: ghcr.io/example/worker\n"
        "    tag: latest\n",
        file_type="k8s",
    )

    assert any(
        f.pattern_id == "helm-structured-image-tag"
        and f.extracted_dep == "ghcr.io/example/worker:latest"
        and f.line_number == 4
        and f.severity == Severity.HIGH
        for f in findings
    )


def test_structured_helm_repository_tag_ignores_version_tag():
    findings = scan(
        "postgres:\n"
        "  image:\n"
        "    repository: postgres\n"
        "    tag: 15.4\n",
        file_type="k8s",
    )

    assert not any(f.pattern_id == "helm-structured-image-tag" for f in findings)


def test_structured_helm_repository_tag_does_not_cross_image_blocks():
    findings = scan(
        "first:\n"
        "  image:\n"
        "    repository: ghcr.io/example/first\n"
        "second:\n"
        "  image:\n"
        "    tag: latest\n",
        file_type="k8s",
    )

    assert not any(f.pattern_id == "helm-structured-image-tag" for f in findings)


def test_flags_ci_yaml_container_and_service_images():
    findings = scan(
        "jobs:\n"
        "  browser:\n"
        "    runs-on: ubuntu-22.04\n"
        "    container: cypress/browsers:node14.19.0-chrome100-ff99-edge\n"
        "    services:\n"
        "      redis:\n"
        "        image: redis:latest\n",
        file_type="ci",
    )

    by_dep = {
        f.extracted_dep: f
        for f in findings
        if f.pattern_id == "ci-yaml-container-image"
    }
    assert by_dep["cypress/browsers:node14.19.0-chrome100-ff99-edge"].severity == Severity.LOW
    assert by_dep["redis:latest"].severity == Severity.HIGH


def test_ci_yaml_container_images_ignore_runner_pool_labels_and_expressions():
    findings = scan(
        "jobs:\n"
        "  test:\n"
        "    pool:\n"
        "      image: windows-2022-secure\n"
        "    strategy:\n"
        "      matrix:\n"
        "        imageName: abtt-ubuntu-2404\n"
        "    container: ${{ matrix.container && fromJSON(format('{\"image\":\"{0}\"}', matrix.container)) }}\n"
        "    image: ${{ variables.linux }}\n"
        "    env:\n"
        "      IMAGE: mcr.microsoft.com/azurelinux/base/core:3.0\n",
        file_type="ci",
    )

    assert not any(f.pattern_id == "ci-yaml-container-image" for f in findings)


def test_k8s_manifest_test_fixture_path_is_ignored():
    findings = scan_rel(
        "        image: myacr.azurecr.io/myimage\n",
        rel_path="Tasks/KubernetesManifestV0/Tests/manifests/deployment.yaml",
        file_type="k8s",
    )

    assert not any(f.pattern_id.startswith("k8s-image") for f in findings)


def test_k8s_manifest_non_test_path_still_reports_untagged_image():
    findings = scan_rel(
        "        image: myacr.azurecr.io/myimage\n",
        rel_path="deploy/manifests/deployment.yaml",
        file_type="k8s",
    )

    assert any(f.pattern_id == "k8s-image-no-tag" for f in findings)


def test_docker_compose_under_test_resources_is_ignored():
    findings = scan_rel(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.21\n",
        rel_path="test/Microsoft.ComponentDetection.VerificationTests/resources/dockercompose/docker-compose.yml",
        file_type="dockerfile",
    )

    assert not any(f.category.value == "container-image" for f in findings)


def test_dockerfile_under_test_resources_is_ignored():
    findings = scan_rel(
        "FROM docker.io/library/ubuntu\n",
        rel_path="test/Microsoft.ComponentDetection.VerificationTests/resources/dockerFiles/ubuntu.dockerfile",
        file_type="dockerfile",
    )

    assert not any(f.category.value == "container-image" for f in findings)


def test_testdata_dockerfile_still_reports_container_image():
    findings = scan_rel(
        "FROM golang:1.16.2-nanoserver-1809\n",
        rel_path="test/testdata/scale_cpu_limits_to_sandbox/Dockerfile",
        file_type="dockerfile",
    )

    assert any(
        f.pattern_id == "dockerfile-from-inventory"
        and f.extracted_dep == "golang:1.16.2-nanoserver-1809"
        for f in findings
    )


def test_test_snapshot_verified_compose_yaml_is_ignored():
    findings = scan_rel(
        "services:\n"
        "  env1-dashboard:\n"
        '    image: "mcr.microsoft.com/dotnet/nightly/aspire-dashboard:latest"\n'
        "  api1:\n"
        '    image: "myimage:latest"\n',
        rel_path=(
            "tests/Aspire.Hosting.Docker.Tests/Snapshots/"
            "DockerComposeTests.MultipleDockerComposeEnvironmentsSupported/env1/"
            "docker-compose.verified.yaml"
        ),
        file_type="dockerfile",
    )

    assert not any(f.category.value == "container-image" for f in findings)


def test_non_test_resources_dockerfile_still_reports_container_image():
    findings = scan_rel(
        "FROM nginx:alpine\n",
        rel_path="deploy/resources/docker/Dockerfile",
        file_type="dockerfile",
    )

    assert any(
        f.pattern_id == "dockerfile-from-inventory"
        and f.extracted_dep == "nginx:alpine"
        for f in findings
    )


def test_k8s_manifest_ignores_your_placeholder_image():
    findings = scan_rel(
        "        image: ghcr.io/your_example/acs-mediated-app:latest\n",
        rel_path="policy-engine/deploy/kubernetes/acs-sidecar-reference/deployment.yaml",
        file_type="k8s",
    )

    assert not any(f.pattern_id.startswith("k8s-") for f in findings)


def test_does_not_treat_base_image_arg_as_yaml_image_key():
    findings = scan(
        "build:\n  args:\n    BASE_IMAGE: tdslibrs.azurecr.io/import/redhat/ubi9:latest\n",
        file_type="dockerfile",
    )

    assert [f for f in findings if f.pattern_id == "k8s-mutable-image-tag"] == []


def test_compose_image_inventory_resolves_shell_default_expansions():
    findings = scan(
        "services:\n"
        "  historian:\n"
        "    image: ${REGISTRY_URL:-mcr.microsoft.com}/fluidframework/routerlicious/historian:${TAG:-latest}\n"
        "  unresolved:\n"
        "    image: ${REGISTRY_NAME}${IMAGE_PREFIX}presidio-analyzer${TAG}\n",
        file_type="dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "compose-image-inventory"
    }
    assert "mcr.microsoft.com/fluidframework/routerlicious/historian:latest" in deps
    assert "${REGISTRY_URL:-mcr.microsoft.com}/fluidframework/routerlicious/historian:${TAG:-latest}" not in deps
    assert "${REGISTRY_NAME}${IMAGE_PREFIX}presidio-analyzer${TAG}" in deps


def test_flags_docker_run_in_script():
    findings = scan("docker run --rm alpine:3.18 sh -c 'echo hello'\n", file_type="script")
    assert any(f.pattern_id == "docker-run-in-script" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_docker_run_ignores_workflow_metadata_label():
    findings = scan("- name: Docker Run and Build Package\n", file_type="github_action")

    assert [f for f in findings if f.pattern_id == "docker-run-in-script"] == []


def test_docker_run_ignores_dockerfile_label_metadata():
    findings = scan(
        'LABEL maintainer="Microsoft" \\\n'
        '      org.label-schema.docker.cmd="docker run microsoft/sqlcmd:$PACKAGE_VERSION"\n',
        file_type="dockerfile",
    )

    assert [f for f in findings if f.pattern_id == "docker-run-in-script"] == []


def test_docker_run_detects_dockerfile_run_instruction():
    findings = scan(
        "RUN docker run --rm alpine:3.18 sh -c 'echo hello'\n",
        file_type="dockerfile",
    )

    assert any(
        f.pattern_id == "docker-run-in-script"
        and f.extracted_dep == "alpine:3.18"
        for f in findings
    )


def test_docker_run_detects_dockerfile_run_continuation():
    findings = scan(
        "RUN set -eux; \\\n"
        "    docker run --rm alpine:3.18 sh -c 'echo hello'\n",
        file_type="dockerfile",
    )

    assert any(
        f.pattern_id == "docker-run-in-script"
        and f.extracted_dep == "alpine:3.18"
        for f in findings
    )


def test_docker_pull_skips_platform_option_value():
    findings = scan(
        "$pullOutput = docker pull --platform $Platform $Image 2>&1\n",
        file_type="script",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-pull-in-script"}
    assert "$Image" in deps
    assert "$Platform" not in deps


def test_docker_pull_stops_before_powershell_pipeline():
    findings = scan(
        "docker pull multiarch/qemu-user-static 2>&1 | ForEach-Object { Write-Info $_ }\n",
        file_type="script",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-pull-in-script"}
    assert "multiarch/qemu-user-static" in deps
    assert "ForEach-Object" not in deps


def test_flags_docker_run_with_variable_image():
    findings = scan(
        "docker run --rm -it quay.io/${ORG}/helmfile:${TAG} sh\n",
        file_type="build",
    )

    assert any(
        f.pattern_id == "docker-run-in-script"
        and f.extracted_dep == "quay.io/${ORG}/helmfile:${TAG}"
        for f in findings
    )


def test_docker_run_skips_volume_and_port_flags():
    findings = scan(
        "docker run -d -p8200:8200 --rm --name vault vault:1.2.0 server\n"
        "docker run --rm -v /:/hostfs:z goharbor/prepare:dev gencert\n",
        file_type="script",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "vault:1.2.0" in deps
    assert "goharbor/prepare:dev" in deps
    assert "/:/hostfs:z" not in deps
    assert "-p8200:8200" not in deps


def test_docker_run_skips_gpus_option_value():
    findings = scan(
        'docker run --rm --gpus all "${{ steps.build.outputs.image }}" nvidia-smi\n',
        file_type="ci",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "${{ steps.build.outputs.image }}" in deps
    assert "all" not in deps


def test_docker_run_skips_variable_option_bundle():
    findings = scan(
        "docker run --name $CONTAINER_NAME --rm -d $DOCKER_NETWORK $DOCKER_IMAGE\n",
        file_type="script",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "$DOCKER_IMAGE" in deps
    assert "$DOCKER_NETWORK" not in deps


def test_docker_run_uses_generic_variable_before_local_command_path():
    findings = scan(
        'docker run --env-file ./env.list --pull=always -v "$SRC:$DST" '
        '"$SWA_DEPLOYMENT_CLIENT" ./bin/staticsites/StaticSitesClient run\n',
        file_type="script",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "$SWA_DEPLOYMENT_CLIENT" in deps
    assert "./bin/staticsites/StaticSitesClient" not in deps


def test_docker_run_treats_container_tag_variable_as_image():
    findings = scan(
        'docker run --rm -v $OUT_DIR:/rpmsdir:z "$CONTAINER_TAG" cp -r /downloadedrpms/. "/rpmsdir"\n',
        file_type="script",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "$CONTAINER_TAG" in deps
    assert "cp" not in deps


def test_docker_run_treats_camel_case_container_tag_variable_as_image():
    findings = scan(
        'docker run --rm -v "$SRC:$DST" "$containerTag" --image-file "$containerInputImage"\n',
        file_type="script",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "$containerTag" in deps
    assert "$containerInputImage" not in deps


def test_docker_run_skips_make_option_variable():
    findings = scan(
        "docker run --rm -i $(DOCKER_FLAGS) --name shellcheck "
        "-v $(CURDIR):/usr/src:ro --workdir /usr/src r.j3ss.co/shellcheck ./test.sh\n",
        file_type="build",
    )

    assert any(
        f.pattern_id == "docker-run-in-script"
        and f.extracted_dep == "r.j3ss.co/shellcheck"
        for f in findings
    )


def test_docker_run_handles_quoted_image_after_flags():
    findings = scan(
        'docker run --rm -p 5000:5000 -e REGISTRY_STORAGE_DELETE_ENABLED=true -idt "registry:local"\n',
        file_type="github_action",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "registry:local" in deps
    assert "5000:5000" not in deps
    assert "REGISTRY_STORAGE_DELETE_ENABLED=true" not in deps


def test_docker_run_skips_container_name_variable_before_image_variable():
    findings = scan(
        'docker run --rm -v "${src_folder}:/ranger" -w "/ranger" '
        '-v "${LOCAL_M2}:${remote_home}/.m2" $container_name $image_name $params\n',
        file_type="script",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "$image_name" in deps
    assert "$container_name" not in deps


def test_docker_run_skips_shell_parameter_option_expansion():
    findings = scan(
        'docker run --rm ${STRIPE_SECRET_KEY:+-e STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"} '
        'clean-eval-$EVAL_NAME\n',
        file_type="script",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "clean-eval-$EVAL_NAME" in deps
    assert not any(dep.startswith("${STRIPE_SECRET_KEY") for dep in deps)


def test_docker_run_skips_attach_flag_values_before_image():
    findings = scan(
        "docker run --init -i --rm -a stderr -a stdout "
        "--user $USER --workdir /vcpkg ${{ variables.LINUX_DOCKER_IMAGE }} ./build.sh\n",
        file_type="ci",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "${{ variables.LINUX_DOCKER_IMAGE }}" in deps
    assert "stderr" not in deps
    assert "stdout" not in deps


def test_docker_run_in_backtick_command_substitution_trims_copy_suffix():
    findings = scan(
        "docker cp `docker run -d ${{ steps.docker_build.outputs.imageid }}`:/out/report.json .\n",
        file_type="ci",
    )

    deps = {f.extracted_dep for f in findings if f.pattern_id == "docker-run-in-script"}
    assert "${{ steps.docker_build.outputs.imageid }}" in deps
    assert not any(dep.endswith(":/out/report.json") for dep in deps)


def test_docker_run_stops_before_stdout_redirection_target():
    findings = scan(
        "docker run -d ${PORT_ARGS} {{ placeholder['image_name'] }} > ${PREFIX}/containerid\n",
        file_type="script",
    )

    assert not any(
        f.pattern_id == "docker-run-in-script"
        and f.extracted_dep == "${PREFIX}/containerid"
        for f in findings
    )


def test_docker_run_ignores_invalid_image_tokens():
    findings = scan(
        'Use "-e POSTGRES_PASSWORD=password" to set it in "docker run".\n'
        "docker run \\\n",
        file_type="agent_instruction",
    )

    assert [f for f in findings if f.pattern_id == "docker-run-in-script"] == []


def test_docker_run_ignores_inline_code_with_no_image():
    findings = scan(
        "The repo-local runner uses ephemeral `docker run --rm` containers.\n",
        file_type="agent_instruction",
    )

    assert [f for f in findings if f.pattern_id == "docker-run-in-script"] == []


def test_docker_run_ignores_bare_inline_code_before_prose():
    findings = scan(
        "Use Docker Compose, a standalone `docker run`, a remote Neo4j instance, or nothing.\n",
        file_type="agent_instruction",
    )

    assert [f for f in findings if f.pattern_id == "docker-run-in-script"] == []


def test_docker_pull_ignores_bare_inline_code_before_prose():
    findings = scan(
        "The image is mirrored internally, so you cannot `docker pull` it either.\n",
        file_type="agent_instruction",
    )

    assert [f for f in findings if f.pattern_id == "docker-pull-in-script"] == []


def test_docker_pull_ignores_descriptive_verb_list():
    findings = scan(
        "docker.go               # Docker pull, inspect, run commands in containers\n",
        file_type="agent_instruction",
    )

    assert [f for f in findings if f.pattern_id == "docker-pull-in-script"] == []
    assert [f for f in findings if f.pattern_id == "docker-run-in-script"] == []


def test_docker_run_ignores_descriptive_commands_phrase():
    findings = scan(
        "Use this package for Docker run commands in test containers.\n",
        file_type="agent_instruction",
    )

    assert [f for f in findings if f.pattern_id == "docker-run-in-script"] == []


def test_docker_run_detects_inline_code_with_image():
    findings = scan(
        "Quickstart with Docker: `docker run -d --name redis redis:8.0.3`.\n",
        file_type="agent_instruction",
    )

    assert any(
        f.pattern_id == "docker-run-in-script"
        and f.extracted_dep == "redis:8.0.3"
        for f in findings
    )


def test_ignores_docker_run_in_non_control_markdown_fence():
    findings = scan(
        "Run the sample:\n\n"
        "```bash\n"
        "docker run --rm redis:latest\n"
        "```\n",
        file_type="agent_instruction",
        name="readme.md",
    )

    assert not any(f.pattern_id == "docker-run-in-script" for f in findings)


def test_ignores_docker_pull_in_non_control_markdown_inline_code():
    findings = scan(
        "Use `docker pull ghcr.io/example/tool:latest` before the demo.\n",
        file_type="agent_instruction",
        name="README.md",
    )

    assert not any(f.pattern_id == "docker-pull-in-script" for f in findings)


def test_ignores_docker_pull_in_non_control_reference_markdown_fence():
    findings = scan_rel(
        "```bash\n"
        "docker pull \"${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/<repo>/$img\"\n"
        "docker pull \"${ACR_NAME}.azurecr.io/app:v1\"\n"
        "```\n",
        "skills/azure-cloud-migrate/references/services/container-apps/cloudrun-deployment-guide.md",
        file_type="agent_instruction",
    )

    assert not any(f.pattern_id == "docker-pull-in-script" for f in findings)


def test_ignores_docker_pull_digest_lookup_markdown_example():
    findings = scan(
        "- To look up a Docker image digest: `docker pull python:3.12-slim && "
        "docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim`\n",
        file_type="agent_instruction",
        name=".github/copilot-instructions.md",
    )

    assert not any(f.pattern_id == "docker-pull-in-script" for f in findings)


def test_detects_docker_pull_digest_lookup_in_script():
    findings = scan(
        "docker pull python:3.12-slim && "
        "docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim\n",
        file_type="script",
    )

    assert any(
        f.pattern_id == "docker-pull-in-script"
        and f.extracted_dep == "python:3.12-slim"
        for f in findings
    )


def test_ignores_docker_run_in_docs_mdx_fence():
    findings = scan_rel(
        "1. Start the database container\n\n"
        "   ```bash frame=\"terminal\" data-disable-copy\n"
        "   docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=secret postgres:15\n"
        "   ```\n",
        "src/frontend/src/content/docs/ja/get-started/what-is-aspire.mdx",
        file_type="agent_instruction",
    )

    assert not any(f.pattern_id == "docker-run-in-script" for f in findings)


def test_ignores_docker_run_in_quick_reference_markdown_fence():
    findings = scan(
        "```bash\n"
        "# Run all tests\n"
        "docker run --rm -v $(pwd):/test chembl:latest python /test/test_chembl.py\n"
        "```\n",
        file_type="agent_instruction",
        name="agents/chembl/tools/ChEMBL/QUICK_REFERENCE.md",
    )

    assert not any(f.pattern_id == "docker-run-in-script" for f in findings)


def test_detects_docker_run_in_prompt_markdown_fence():
    findings = scan(
        "Run without local dependencies:\n\n"
        "```bash\n"
        "docker run --rm -i mcr.microsoft.com/lisa/runtime:latest lisa -r runbook.yml\n"
        "```\n",
        file_type="agent_instruction",
        name=".github/prompts/install-lisa.prompt.md",
    )

    assert any(
        f.pattern_id == "docker-run-in-script"
        and f.extracted_dep == "mcr.microsoft.com/lisa/runtime:latest"
        for f in findings
    )


def test_detects_docker_run_in_skill_markdown_fence():
    findings = scan(
        "Run the required service:\n\n"
        "```bash\n"
        "docker run --rm redis:8.0.3\n"
        "```\n",
        file_type="agent_instruction",
        name="SKILL.md",
    )

    assert any(
        f.pattern_id == "docker-run-in-script"
        and f.extracted_dep == "redis:8.0.3"
        for f in findings
    )


def test_detects_docker_pull_in_skill_markdown_fence():
    findings = scan(
        "Pull the required image:\n\n"
        "```bash\n"
        "docker pull ghcr.io/example/tool:v1\n"
        "```\n",
        file_type="agent_instruction",
        name="SKILL.md",
    )

    assert any(
        f.pattern_id == "docker-pull-in-script"
        and f.extracted_dep == "ghcr.io/example/tool:v1"
        for f in findings
    )


def test_docker_run_ignores_shell_splat_wrapper_args():
    findings = scan(
        'exec docker run -e TOKEN="$TOKEN" "$@"\n',
        file_type="script",
    )

    assert [f for f in findings if f.pattern_id == "docker-run-in-script"] == []


def test_docker_run_ignores_throw_error_string():
    findings = scan(
        'if ($LASTEXITCODE -ne 0) { throw "docker run failed for $ContainerName." }\n',
        file_type="script",
    )

    assert [f for f in findings if f.pattern_id == "docker-run-in-script"] == []


def test_flags_tag_only_images_passed_to_download_helper():
    findings = scan(
        "run: bash ./scripts/download_docker_images.sh "
        "ghcr.io/github/gh-aw-firewall/agent:0.25.49 "
        "ghcr.io/github/pinned:1.2@sha256:abcdef1234567890\n",
        file_type="ci",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "ci-image-helper-argument"
    }
    assert "ghcr.io/github/gh-aw-firewall/agent:0.25.49" in deps
    assert "ghcr.io/github/pinned:1.2@sha256:abcdef1234567890" not in deps


def test_flags_ci_image_environment_variable():
    findings = scan(
        "env:\n  DIFC_PROXY_IMAGE: 'ghcr.io/github/gh-aw-mcpg:v0.3.9'\n",
        file_type="ci",
    )

    assert any(
        f.pattern_id == "ci-image-env-var"
        and f.extracted_dep == "ghcr.io/github/gh-aw-mcpg:v0.3.9"
        for f in findings
    )


def test_does_not_flag_digest_pinned_ci_image_environment_variable():
    findings = scan(
        "env:\n  PROXY_IMAGE: ghcr.io/github/gh-aw-mcpg:v0.3.9@sha256:abcdef1234567890\n",
        file_type="ci",
    )

    assert not any(f.pattern_id == "ci-image-env-var" for f in findings)


def test_flags_generated_json_container_image():
    findings = scan(
        '{"mcp": {"container": "ghcr.io/github/github-mcp-server:v1.0.4"}}\n',
        file_type="ci",
    )

    assert any(
        f.pattern_id == "json-container-image"
        and f.extracted_dep == "ghcr.io/github/github-mcp-server:v1.0.4"
        for f in findings
    )


def test_does_not_flag_digest_pinned_generated_json_container_image():
    findings = scan(
        '{"container": "ghcr.io/github/github-mcp-server:v1.0.4@sha256:abcdef1234567890"}\n',
        file_type="ci",
    )

    assert not any(f.pattern_id == "json-container-image" for f in findings)


def test_honors_docker_detector_suppression_comment():
    findings = scan(
        '# DisableDockerDetector "Playground/demo application"\n'
        "FROM node:20 AS build\n"
        "FROM nginx:alpine\n",
        file_type="dockerfile",
    )

    assert findings == []


def test_dockerfile_from_inventory_resolves_arg_default_image():
    findings = scan(
        "ARG IMAGE_NAME=mcr.microsoft.com/azurelinux/base/nodejs:20\n"
        "FROM $IMAGE_NAME AS build\n",
        file_type="dockerfile",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "dockerfile-from-inventory"
    }
    assert "mcr.microsoft.com/azurelinux/base/nodejs:20" in deps
    assert "$IMAGE_NAME" not in deps


def test_dockerfile_from_inventory_ignores_unresolved_arg_image():
    findings = scan(
        "ARG BASE_IMAGE\n"
        "FROM ${BASE_IMAGE} AS production\n",
        file_type="dockerfile",
    )

    assert not any(
        f.pattern_id == "dockerfile-from-inventory"
        and f.extracted_dep == "${BASE_IMAGE}"
        for f in findings
    )


def test_flags_aspire_typescript_apphost_container_literals():
    findings = scan_rel(
        "import { createBuilder } from './.aspire/modules/aspire.mjs';\n"
        "const builder = await createBuilder();\n"
        "await builder.addContainer('web', 'redis:latest');\n"
        'await builder.addContainer("api", "myregistry/myapp");\n'
        'await builder.addContainer("worker", "mcr.microsoft.com/dotnet/runtime:10.0");\n'
        'await composeFile.addService("validation-sidecar", { image: "busybox" });\n'
        'await builder.addContainer("pinned", "registry.example.com/app@sha256:abcdef");\n',
        "tests/PolyglotAppHosts/Demo/TypeScript/apphost.mts",
        file_type="source_code",
    )

    findings_by_dep = {
        f.extracted_dep: f
        for f in findings
        if f.pattern_id == "aspire-source-container-image"
    }
    assert findings_by_dep["redis:latest"].severity == Severity.HIGH
    assert findings_by_dep["myregistry/myapp"].severity == Severity.HIGH
    assert findings_by_dep["mcr.microsoft.com/dotnet/runtime:10.0"].severity == Severity.LOW
    assert "registry.example.com/app@sha256:abcdef" not in findings_by_dep
    assert any(
        f.pattern_id == "aspire-source-service-image"
        and f.extracted_dep == "busybox"
        and f.severity == Severity.HIGH
        for f in findings
    )


def test_flags_aspire_python_apphost_container_literals_and_base_images():
    findings = scan_rel(
        "from aspire_app import create_builder\n"
        "with create_builder() as builder:\n"
        '    builder.add_container("api", "nginx")\n'
        "    api.publish_as_migration_bundle(\n"
        "        publish_container=True,\n"
        '        base_image="mcr.microsoft.com/dotnet/runtime:10.0")\n',
        "tests/PolyglotAppHosts/Demo/Python/apphost.py",
        file_type="source_code",
    )

    assert any(
        f.pattern_id == "aspire-source-container-image"
        and f.extracted_dep == "nginx"
        and f.severity == Severity.HIGH
        for f in findings
    )
    assert any(
        f.pattern_id == "aspire-source-base-image"
        and f.extracted_dep == "mcr.microsoft.com/dotnet/runtime:10.0"
        and f.severity == Severity.LOW
        for f in findings
    )


def test_aspire_source_container_scan_ignores_placeholder_image_names():
    findings = scan_rel(
        "from aspire_app import create_builder\n"
        "with create_builder() as builder:\n"
        '    builder.add_container("resource", "image")\n'
        '    builder.add_container("sample", "myimage")\n'
        '    builder.add_container("api", "nginx")\n'
        '    builder.add_container("worker", "busybox")\n',
        "tests/PolyglotAppHosts/Demo/Python/apphost.py",
        file_type="source_code",
    )

    deps = {
        f.extracted_dep
        for f in findings
        if f.pattern_id == "aspire-source-container-image"
    }
    assert "image" not in deps
    assert "myimage" not in deps
    assert {"nginx", "busybox"} <= deps


def test_aspire_source_container_scan_ignores_resource_container_apis_and_comments():
    findings = scan_rel(
        "import { createBuilder } from './.aspire/modules/aspire.mjs';\n"
        "const builder = await createBuilder();\n"
        "const db = await cosmos.addDatabase('db');\n"
        "await db.addContainer('orders', '/orderId');\n"
        "// await builder.addContainer('api', 'redis:latest');\n",
        "tests/PolyglotAppHosts/Demo/TypeScript/apphost.mts",
        file_type="source_code",
    )

    assert not any(f.pattern_id == "aspire-source-container-image" for f in findings)


def test_aspire_source_container_scan_ignores_test_code_strings():
    findings = scan_rel(
        "import { createBuilder } from './.aspire/modules/aspire.mjs';\n"
        "const sample = \"await builder.addContainer('api', 'nginx')\";\n",
        "extension/src/test/parsers.test.ts",
        file_type="source_code",
    )

    assert not any(f.pattern_id == "aspire-source-container-image" for f in findings)


def test_fixture_dockerfile():
    fixture = Path(__file__).parent.parent / "fixtures" / "dockerfiles" / "Dockerfile"
    scanner = ContainerImageScanner(Config())
    target = FileTarget(path=fixture, rel_path="Dockerfile", file_type="dockerfile")
    findings = scanner.scan_file(target)
    assert len(findings) >= 2
    pattern_ids = {f.pattern_id for f in findings}
    assert "unpinned-dockerfile-from" in pattern_ids or "dockerfile-from-no-tag" in pattern_ids
