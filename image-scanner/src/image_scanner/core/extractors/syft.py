"""Default SBOM extractor: Anchore syft (daemonless, registry-native).

syft can read an image straight from a registry without a Docker daemon and
emit CycloneDX JSON, with strong OS-package, language-package, and binary
cataloging. Pull credentials are passed via ``SYFT_REGISTRY_AUTH_*`` env so
secrets never appear on the command line.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from supplydrift_sandbox import NetworkPolicy, SandboxError

from ..._sandbox import tool_sandbox
from ...auth.registry_auth import docker_cred_key, read_docker_credentials
from ...models import RegistryAuth
from .base import ExtractorError, SbomExtractor


class SyftExtractor(SbomExtractor):
    name = "syft"

    def __init__(self, syft_bin: str = "syft", timeout: int = 600):
        self.syft_bin = syft_bin
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.syft_bin) is not None

    def _env(self, auth: RegistryAuth | None) -> dict[str, str]:
        # The sandbox executor starts from an allowlist, so no runner token,
        # AWS/kube credentials, Docker config, proxy setting, or parent HOME is
        # inherited.  Only this target's resolved pull credential is added.
        env = {"SYFT_CHECK_FOR_APP_UPDATE": "false"}
        if not auth:
            return env
        if auth.has_credentials:
            # syft single-registry credential env vars (never on argv).
            env["SYFT_REGISTRY_AUTH_AUTHORITY"] = auth.registry
            if auth.token:
                env["SYFT_REGISTRY_AUTH_TOKEN"] = auth.token
            if auth.username:
                env["SYFT_REGISTRY_AUTH_USERNAME"] = auth.username
            if auth.password:
                env["SYFT_REGISTRY_AUTH_PASSWORD"] = auth.password
            # Default to TLS; registries are https unless explicitly local.
            env.setdefault("SYFT_REGISTRY_INSECURE_USE_HTTP", "false")
        return env

    @staticmethod
    def _resolve_auth(auth: RegistryAuth | None) -> RegistryAuth | None:
        """Resolve Docker config in the trusted parent; never expose it to Syft."""

        if not auth or not auth.docker_config_path:
            return auth
        username, secret = read_docker_credentials(
            docker_cred_key(auth.registry), config_path=auth.docker_config_path
        )
        if not secret:
            raise ExtractorError(
                f"no pull credential for {auth.registry or 'the registry'} in the configured "
                "Docker credential source"
            )
        return RegistryAuth(
            username=username,
            password=secret,
            registry=auth.registry,
            provider="docker",
        )

    @staticmethod
    def _registry_host(image_ref: str, auth: RegistryAuth | None) -> str:
        if auth and auth.registry:
            return auth.registry
        reference = image_ref.split("@", 1)[0]
        first = reference.split("/", 1)[0]
        # A colon in a slash-free short name is its tag (``nginx:latest``),
        # not a registry port. Registry host heuristics apply only when a
        # repository path follows the candidate host.
        if "/" in reference and ("." in first or ":" in first or first == "localhost"):
            return first
        return "registry-1.docker.io"

    def extract(self, image_ref: str, auth: RegistryAuth | None = None) -> dict[str, Any]:
        if not self.available():
            raise ExtractorError(
                f"'{self.syft_bin}' not found on PATH. Install syft "
                "(https://github.com/anchore/syft) or use --dry-run."
            )
        auth = self._resolve_auth(auth)
        # 'registry:' forces a daemonless pull straight from the registry.
        cmd = [self.syft_bin, f"registry:{image_ref}", "-o", "cyclonedx-json", "-q"]
        try:
            completed = tool_sandbox.run(
                "syft",
                cmd,
                environment=self._env(auth),
                network_policy=NetworkPolicy.PROXY,
                allowed_host=self._registry_host(image_ref, auth),
                timeout_seconds=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ExtractorError(f"syft timed out after {self.timeout}s for {image_ref}") from exc
        except (OSError, SandboxError) as exc:
            raise ExtractorError(f"syft sandbox failed for {image_ref}: {exc}") from exc
        if completed.returncode != 0:
            raise ExtractorError(
                f"syft failed for {image_ref} (exit {completed.returncode}): "
                f"{completed.stderr.strip()[:500]}"
            )
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ExtractorError(f"syft returned invalid JSON for {image_ref}") from exc
