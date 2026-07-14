"""Tests for child-process env hardening (SD-09): the runner's platform token
and the platform's secret key must not leak into subprocesses that touch
untrusted input (syft/grype on attacker images, kubectl on clusters, the aws CLI).
"""
from __future__ import annotations

from image_scanner._env import SENSITIVE_ENV_VARS, child_env
from image_scanner.core.extractors.syft import SyftExtractor
from image_scanner.models import RegistryAuth


def test_child_env_strips_platform_secrets(monkeypatch):
    monkeypatch.setenv("SUPPLYDRIFT_RUNNER_TOKEN", "sdr_secret")
    monkeypatch.setenv("SUPPLYDRIFT_SECRET_KEY", "fernet-key")
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA")
    env = child_env()
    for var in SENSITIVE_ENV_VARS:
        assert var not in env
    # Everything a child tool actually needs is preserved.
    assert env["PATH"] == "/usr/bin"
    assert env["AWS_ACCESS_KEY_ID"] == "AKIA"


def test_child_env_merges_extra_over_scrubbed(monkeypatch):
    monkeypatch.setenv("SUPPLYDRIFT_RUNNER_TOKEN", "sdr_secret")
    env = child_env({"SYFT_REGISTRY_AUTH_TOKEN": "pull-tok"})
    assert env["SYFT_REGISTRY_AUTH_TOKEN"] == "pull-tok"
    assert "SUPPLYDRIFT_RUNNER_TOKEN" not in env


def test_syft_env_excludes_platform_secrets(monkeypatch):
    monkeypatch.setenv("SUPPLYDRIFT_RUNNER_TOKEN", "sdr_secret")
    monkeypatch.setenv("SUPPLYDRIFT_SECRET_KEY", "fernet-key")
    ext = SyftExtractor()
    # No auth is anonymous and carries no ambient credential chain.
    env = ext._env(None)
    assert "SUPPLYDRIFT_RUNNER_TOKEN" not in env and "SUPPLYDRIFT_SECRET_KEY" not in env
    assert "AWS_ACCESS_KEY_ID" not in env and "DOCKER_CONFIG" not in env
    # With credentials: pull creds present, platform secrets absent.
    env = ext._env(RegistryAuth(username="u", password="p", registry="r"))
    assert env.get("SYFT_REGISTRY_AUTH_USERNAME") == "u"
    assert "SUPPLYDRIFT_RUNNER_TOKEN" not in env and "SUPPLYDRIFT_SECRET_KEY" not in env


def test_syft_resolves_docker_hub_config_in_parent(monkeypatch):
    captured = {}

    def fake_read(registry, *, config_path):
        captured.update(registry=registry, config_path=config_path)
        return "hub-user", "hub-token"

    monkeypatch.setattr(
        "image_scanner.core.extractors.syft.read_docker_credentials", fake_read
    )
    resolved = SyftExtractor._resolve_auth(
        RegistryAuth(
            registry="registry-1.docker.io",
            docker_config_path="/secrets/docker-config.json",
            provider="docker",
        )
    )
    assert captured["registry"] == "https://index.docker.io/v1/"
    assert resolved.username == "hub-user" and resolved.password == "hub-token"
    assert not resolved.docker_config_path


def test_syft_short_name_tag_is_not_treated_as_registry_port():
    assert SyftExtractor._registry_host("nginx:latest", None) == "registry-1.docker.io"
    assert SyftExtractor._registry_host("localhost:5000/acme/app:1", None) == "localhost:5000"


def test_k8s_collector_child_env_strips_secrets_keeps_aws(monkeypatch):
    from k8s_cartographer import collector

    monkeypatch.setenv("SUPPLYDRIFT_RUNNER_TOKEN", "sdr_secret")
    monkeypatch.setenv("SUPPLYDRIFT_SECRET_KEY", "fernet-key")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = collector._child_env({"AWS_SESSION_TOKEN": "sts-tok"})
    assert env["AWS_SESSION_TOKEN"] == "sts-tok"   # EKS exec-plugin creds preserved
    assert env["PATH"] == "/usr/bin"
    assert "SUPPLYDRIFT_RUNNER_TOKEN" not in env and "SUPPLYDRIFT_SECRET_KEY" not in env
