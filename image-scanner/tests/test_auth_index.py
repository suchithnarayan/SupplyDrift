"""Tests for the RegistryAuthIndex (services reuse registry credentials)."""
from __future__ import annotations

from conftest import registry_cfg

from image_scanner.auth import registry_auth as registry_auth_module
from image_scanner.auth.aws import AwsSession
from image_scanner.auth.index import RegistryAuthIndex


def _ecr_session():
    def runner(cmd, env=None):
        return "ecr-token\n" if "get-login-password" in " ".join(cmd) else "{}"

    return AwsSession.from_config({"regions": ["us-east-1"]}, runner=runner)


def make_index():
    return RegistryAuthIndex.from_registries(
        [
            registry_cfg("hub", "dockerhub", {"auth": {"username": "dh", "password": "dhpat"}}),
            registry_cfg("ghcr", "ghcr", {"auth": {"username": "gh", "token": "ghpat"}}),
            registry_cfg("harbor", "harbor", {"registry": "harbor.acme.io", "auth": {"username": "robot$x", "password": "s3"}}),
            registry_cfg("ecr", "ecr", {"account_id": "123456789012"}, aws_session=_ecr_session()),
        ]
    )


def test_dockerhub_image_reuses_registry_credentials():
    auth = make_index().auth_for("registry-1.docker.io", "acme/api")
    assert auth and auth.username == "dh" and auth.password == "dhpat"


def test_docker_io_short_host_matches():
    auth = make_index().auth_for("docker.io", "library/nginx")
    assert auth and auth.password == "dhpat"


def test_ghcr_image_reuses_token_as_password():
    auth = make_index().auth_for("ghcr.io", "acme/web")
    assert auth and auth.username == "gh" and auth.password == "ghpat"


def test_harbor_image_reuses_robot_credential():
    auth = make_index().auth_for("harbor.acme.io", "team/app")
    assert auth and auth.username == "robot$x" and auth.password == "s3"


def test_ecr_image_mints_via_session():
    auth = make_index().auth_for("123456789012.dkr.ecr.us-east-1.amazonaws.com", "payments-api")
    assert auth and auth.username == "AWS" and auth.password == "ecr-token"


def test_unmatched_registry_returns_none():
    assert make_index().auth_for("registry.internal.acme.com", "backup") is None


def test_anonymous_registry_does_not_consume_ambient_docker_auth(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("ambient Docker credentials must not be read")

    monkeypatch.setattr(registry_auth_module, "read_docker_credentials", unexpected)
    for auth_config in (None, {"provider": "none"}):
        connection = {} if auth_config is None else {"auth": auth_config}
        index = RegistryAuthIndex.from_registries(
            [registry_cfg("hub", "dockerhub", connection)]
        )
        assert index.auth_for("registry-1.docker.io", "library/nginx") is None


def test_docker_provider_resolves_only_its_configured_path(monkeypatch):
    captured = {}

    def fake_read(registry, *, config_path):
        captured.update(registry=registry, config_path=config_path)
        return "configured-user", "configured-secret"

    monkeypatch.setattr(registry_auth_module, "read_docker_credentials", fake_read)
    index = RegistryAuthIndex.from_registries(
        [
            registry_cfg(
                "hub",
                "dockerhub",
                {
                    "auth": {
                        "provider": "docker",
                        "config_path": "/trusted/docker-config.json",
                    }
                },
            )
        ]
    )

    auth = index.auth_for("registry-1.docker.io", "library/nginx")

    assert captured == {
        "registry": "https://index.docker.io/v1/",
        "config_path": "/trusted/docker-config.json",
    }
    assert auth and auth.username == "configured-user"
    assert auth.password == "configured-secret"


def test_unmatched_ecr_uses_aws_fallback():
    index = RegistryAuthIndex.from_registries([])  # no configured registries
    auth = index.auth_for(
        "999.dkr.ecr.eu-west-1.amazonaws.com", "app", aws_fallback=_ecr_session()
    )
    assert auth and auth.username == "AWS" and auth.password == "ecr-token"


def test_describe_reports_configured_source():
    desc = make_index().describe("ghcr.io", "acme/web")
    assert desc["configured"] and desc["source"] == "ghcr" and desc["type"] == "ghcr"
