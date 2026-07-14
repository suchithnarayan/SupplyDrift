"""Tests for registry pull-credential resolution (auth/registry_auth.py)."""
from __future__ import annotations

import base64
import json

import pytest

from image_scanner.auth import registry_auth as ra


# --- registry-host inference (ECR only) ------------------------------------- #
@pytest.mark.parametrize(
    "registry,expected",
    [
        ("123456789012.dkr.ecr.us-east-1.amazonaws.com", "ecr"),
        ("registry-1.docker.io", None),
        ("ghcr.io", None),
        ("harbor.acme.io", None),
        ("", None),
    ],
)
def test_provider_for_registry(registry, expected):
    assert ra.provider_for_registry(registry) == expected
    assert ra.is_ecr_registry(registry) == (expected == "ecr")


# --- static / env auth ------------------------------------------------------ #
def test_resolve_static_inline():
    auth = ra.resolve_static_auth({"username": "u", "password": "p"}, registry="r")
    assert auth.username == "u" and auth.password == "p" and auth.provider == "static"


def test_resolve_static_from_env(monkeypatch):
    monkeypatch.setenv("U", "robot")
    monkeypatch.setenv("P", "secret")
    auth = ra.resolve_static_auth({"username_env": "U", "password_env": "P"})
    assert auth.username == "robot" and auth.password == "secret" and auth.provider == "env"


def test_resolve_static_empty_returns_none():
    assert ra.resolve_static_auth({}) is None
    assert ra.resolve_static_auth(None) is None


# --- resolve_auth provider dispatch ----------------------------------------- #
def test_resolve_auth_none_is_anonymous():
    auth = ra.resolve_auth({"provider": "none"}, registry="r")
    assert auth.anonymous and auth.provider == "none"


def test_resolve_auth_docker_config_path():
    auth = ra.resolve_auth({"provider": "docker", "config_path": "/tmp/cfg"}, registry="r")
    assert auth.docker_config_path == "/tmp/cfg" and auth.provider == "docker"


def test_resolve_auth_docker_uses_resolved_default_config(monkeypatch, tmp_path):
    docker_dir = tmp_path / ".docker"
    docker_dir.mkdir()
    monkeypatch.setenv("DOCKER_CONFIG", str(docker_dir))
    auth = ra.resolve_auth({"provider": "docker"}, registry="registry-1.docker.io")
    assert auth.docker_config_path == str(docker_dir / "config.json")


def test_resolve_auth_ecr_provider_rejected():
    with pytest.raises(RuntimeError, match="aws_auth"):
        ra.resolve_auth({"provider": "ecr", "region": "us-east-1"})


def test_resolve_auth_unknown_provider():
    with pytest.raises(RuntimeError, match="unknown auth provider"):
        ra.resolve_auth({"provider": "magic"})


# --- docker config.json reading --------------------------------------------- #
def test_read_docker_credentials_inline(tmp_path):
    blob = base64.b64encode(b"robot:tok").decode()
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"auths": {"ghcr.io": {"auth": blob}}}))
    user, secret = ra.read_docker_credentials("ghcr.io", config_path=str(cfg))
    assert user == "robot" and secret == "tok"


def test_read_docker_credentials_helper(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"credHelpers": {"ghcr.io": "test"}}))

    def fake_helper(helper, server):
        return json.dumps({"Username": "u", "Secret": "s"})

    user, secret = ra.read_docker_credentials("ghcr.io", config_path=str(cfg), cred_runner=fake_helper)
    assert user == "u" and secret == "s"


def test_docker_cred_key_maps_hub():
    assert ra.docker_cred_key("docker.io") == ra.DOCKER_HUB_CRED_KEY
    assert ra.docker_cred_key("ghcr.io") == "ghcr.io"


# --- credential-helper arg0 allowlist (SD-09) ------------------------------- #
@pytest.mark.parametrize(
    "helper",
    ["../evil", "a/b", "a.b", "ecr login", "", "helper;rm", "$(id)"],
)
def test_default_cred_runner_rejects_unsafe_helper_name(helper):
    # A helper name from config.json is interpolated into docker-credential-{name};
    # anything outside [A-Za-z0-9_-]+ must be refused before exec.
    with pytest.raises(RuntimeError, match="unsafe"):
        ra._default_cred_runner(helper, "ghcr.io")


def test_read_docker_credentials_skips_unsafe_helper_falls_back_to_inline(tmp_path):
    # A malicious credHelpers entry must not exec; it falls through to inline auth.
    blob = base64.b64encode(b"robot:tok").decode()
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "credHelpers": {"ghcr.io": "../../../../bin/sh"},
        "auths": {"ghcr.io": {"auth": blob}},
    }))
    user, secret = ra.read_docker_credentials("ghcr.io", config_path=str(cfg))
    assert user == "robot" and secret == "tok"
