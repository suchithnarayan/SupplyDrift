"""Registry *pull* credential resolution (the data plane).

This module resolves the unified ``auth`` block that registry connectors carry,
into a :class:`~image_scanner.models.RegistryAuth` the extractor can use to pull
an image. It covers the non-cloud means:

    auth: { provider: none }                                   # anonymous
    auth: { provider: docker }                                 # ~/.docker/config.json + helpers
    auth: { provider: docker, config_path: /run/secrets/dkr }  # explicit docker config
    auth: { provider: env, username_env: GHCR_USER, password_env: GHCR_TOKEN }
    auth: { provider: static, username: robot, password: s3cr3t }   # discouraged

AWS/ECR credentials are NOT resolved here — they come from the dedicated AWS auth
component (:mod:`image_scanner.auth.aws`) driven by an ``aws_auth`` block. A
``provider: ecr`` here is rejected with a pointer to ``aws_auth``.

Returning ``None`` means an anonymous pull. Docker credentials are always
resolved in this trusted parent component before Syft enters its sandbox; the
child never receives a Docker config path or an ambient credential chain.
"""
from __future__ import annotations

import os
import re
import subprocess
from typing import Any, Callable

from ..models import RegistryAuth


def _env(name: str | None) -> str:
    if not name:
        return ""
    return os.environ.get(str(name), "")


# Docker Hub's credential key in ~/.docker/config.json.
DOCKER_HUB_CRED_KEY = "https://index.docker.io/v1/"

# A credential-helper name comes from a (potentially attacker-supplied) docker
# config.json and is interpolated into the argv0 ``docker-credential-{helper}``.
# Restrict it to the character set real helper names use so a value containing
# path separators, dots, or shell metacharacters can never redirect the exec to
# an arbitrary binary.
_HELPER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def docker_cred_key(registry: str) -> str:
    """Map a registry host to the key Docker uses in config.json.

    Docker Hub is stored under a special legacy key; every other registry is
    keyed by its hostname.
    """
    host = (registry or "").lower()
    if host in ("", "docker.io", "registry-1.docker.io", "index.docker.io"):
        return DOCKER_HUB_CRED_KEY
    return registry


def _docker_config_path(config_path: str | None) -> str:
    if config_path:
        p = os.path.expanduser(config_path)
    else:
        p = os.environ.get("DOCKER_CONFIG") or os.path.expanduser("~/.docker")
        p = os.path.expanduser(p)
    if os.path.isdir(p):
        return os.path.join(p, "config.json")
    return p


def _default_cred_runner(helper: str, server: str) -> str:
    if not _HELPER_NAME_RE.match(helper or ""):
        raise RuntimeError(
            f"refusing to run docker credential helper with unsafe name {helper!r} "
            "(must match [A-Za-z0-9_-]+)"
        )
    proc = subprocess.run(
        [f"docker-credential-{helper}", "get"],
        input=server,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip())
    return proc.stdout


def read_docker_credentials(
    registry: str = DOCKER_HUB_CRED_KEY,
    config_path: str | None = None,
    cred_runner: Callable[[str, str], str] | None = None,
) -> tuple[str, str]:
    """Read ``(username, secret)`` for ``registry`` from an existing docker login.

    Mirrors how Docker resolves credentials: a configured credential helper
    (``credHelpers[registry]`` or the global ``credsStore``) takes precedence,
    otherwise the inline base64 ``auths[registry].auth`` entry is decoded. This
    is what makes the "login is already taken care of" path work without
    re-declaring secrets. Returns ``("", "")`` when nothing is configured.
    """
    import base64
    import json as _json

    path = _docker_config_path(config_path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = _json.load(fh)
    except (OSError, _json.JSONDecodeError):
        return "", ""

    helper = (cfg.get("credHelpers") or {}).get(registry) or cfg.get("credsStore")
    if helper:
        try:
            out = (cred_runner or _default_cred_runner)(helper, registry)
            data = _json.loads(out or "{}")
            secret = data.get("Secret", "") or ""
            if secret:
                return data.get("Username", "") or "", secret
        except (RuntimeError, ValueError, OSError):
            pass  # fall through to inline auths

    entry = (cfg.get("auths") or {}).get(registry) or {}
    blob = entry.get("auth")
    if blob:
        try:
            decoded = base64.b64decode(blob).decode("utf-8")
            if ":" in decoded:
                user, secret = decoded.split(":", 1)
                if secret:
                    return user, secret
        except (ValueError, UnicodeDecodeError):
            pass
    if entry.get("identitytoken"):
        return entry.get("username", "") or "", entry["identitytoken"]
    return "", ""


def docker_credential_helper_for(registry: str, config_path: str | None = None) -> str | None:
    """Return the docker credential helper configured for ``registry``, if any.

    Checks ``credHelpers[<registry>]`` first, then the global ``credsStore``
    (which applies to every registry not in ``credHelpers``). Returns the helper
    name (e.g. ``ecr-login``, ``desktop``) or ``None``.
    """
    import json as _json

    path = _docker_config_path(config_path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = _json.load(fh)
    except (OSError, _json.JSONDecodeError):
        return None
    cred_helpers = cfg.get("credHelpers") or {}
    helper = cred_helpers.get(docker_cred_key(registry)) or cred_helpers.get(registry)
    helper = helper or cfg.get("credsStore")
    return helper or None


def helper_auth_for(
    registry: str,
    config_path: str | None = None,
    cred_runner: Callable[[str, str], str] | None = None,
) -> RegistryAuth | None:
    """Resolve pull credentials from a configured docker credential helper.

    Returns ``None`` when no helper is configured for the registry. Helpers
    self-refresh, so this is preferred over re-declaring secrets when available.
    """
    if not docker_credential_helper_for(registry, config_path):
        return None
    user, secret = read_docker_credentials(
        docker_cred_key(registry), config_path=config_path, cred_runner=cred_runner
    )
    if secret:
        return RegistryAuth(username=user, password=secret, registry=registry, provider="docker")
    return None


def provider_for_registry(registry: str) -> str | None:
    """Infer a cloud auth provider from a registry hostname. Only ECR is supported."""
    host = (registry or "").lower()
    if ".dkr.ecr." in host and host.endswith(".amazonaws.com"):
        return "ecr"
    return None


def is_ecr_registry(registry: str) -> bool:
    return provider_for_registry(registry) == "ecr"


def resolve_static_auth(auth_cfg: dict[str, Any] | None, registry: str = "") -> RegistryAuth | None:
    """Resolve a static/env-backed auth block into RegistryAuth (or None)."""
    if not auth_cfg:
        return None
    username = auth_cfg.get("username", "") or _env(auth_cfg.get("username_env"))
    password = auth_cfg.get("password", "") or _env(auth_cfg.get("password_env"))
    token = auth_cfg.get("token", "") or _env(auth_cfg.get("token_env"))
    explicit = bool(auth_cfg.get("username") or auth_cfg.get("password") or auth_cfg.get("token"))
    auth = RegistryAuth(
        username=username,
        password=password,
        token=token,
        registry=registry,
        provider="static" if explicit else "env",
    )
    return None if auth.empty else auth


def _infer_provider(cfg: dict[str, Any]) -> str:
    """Derive a provider when an auth block omits ``provider``."""
    if any(cfg.get(k) for k in ("username", "password", "token")):
        return "static"
    if any(cfg.get(k) for k in ("username_env", "password_env", "token_env")):
        return "env"
    if cfg.get("config_path") or cfg.get("docker_config"):
        return "docker"
    return "none"


def resolve_auth(auth_cfg: dict[str, Any] | None, registry: str = "") -> RegistryAuth | None:
    """Resolve a unified ``auth`` block (non-cloud) into a RegistryAuth.

    ``None`` means an anonymous pull. A ``provider: ecr`` is rejected — ECR
    auth comes from the ``aws_auth`` block instead.
    """
    if not auth_cfg:
        return None
    provider = str(auth_cfg.get("provider") or _infer_provider(auth_cfg)).lower()

    if provider in ("none", "anonymous"):
        return RegistryAuth(registry=registry, anonymous=True, provider="none")
    if provider == "docker":
        path = auth_cfg.get("config_path") or auth_cfg.get("docker_config") or ""
        return RegistryAuth(
            registry=registry,
            docker_config_path=_docker_config_path(str(path) if path else None),
            provider="docker",
        )
    if provider in ("static", "env"):
        return resolve_static_auth(auth_cfg, registry=registry)
    if provider in ("ecr", "gcp", "azure"):
        raise RuntimeError(
            f"auth provider '{provider}' is not a registry credential. Configure AWS "
            "access for ECR/ECS/EKS via an 'aws_auth' block instead."
        )
    raise RuntimeError(
        f"unknown auth provider '{provider}'. Use one of: none, static, env, docker"
    )


def resolve_pull_auth(
    auth_cfg: dict[str, Any] | None, registry: str = ""
) -> RegistryAuth | None:
    """Resolve one explicitly selected registry credential for a Syft child.

    Omitted/anonymous auth never consults ambient Docker state. A Docker config
    is read only when ``provider: docker`` was selected, and only the credential
    for ``registry`` is returned; the config path itself is not exposed to Syft.
    """
    resolved = resolve_auth(auth_cfg, registry=registry)
    if not resolved or resolved.anonymous:
        return None
    if resolved.docker_config_path:
        username, secret = read_docker_credentials(
            docker_cred_key(registry), config_path=resolved.docker_config_path
        )
        if not secret:
            return None
        return RegistryAuth(
            username=username,
            password=secret,
            registry=registry,
            provider="docker",
        )
    if not resolved.has_credentials:
        return None
    # Registry PATs paired with a username use HTTP Basic. Token-only providers
    # retain the dedicated bearer-token field.
    token_as_password = resolved.token if resolved.username and not resolved.password else ""
    return RegistryAuth(
        username=resolved.username,
        password=resolved.password or token_as_password,
        token="" if token_as_password else resolved.token,
        registry=registry,
        provider=resolved.provider,
        expires_at=resolved.expires_at,
    )
