"""AWS authentication component, shared by the ECR, ECS, and EKS connectors.

One ``aws_auth`` config block describes how to obtain AWS credentials by any
supported means; this module resolves it into an :class:`AwsSession` that every
AWS-backed connector uses to shell out to the ``aws`` CLI identically. Nothing
else in the scanner knows how AWS auth works.

Supported means (declare what fits the environment; combine ``role_arn`` with a
base identity for cross-account access)::

    aws_auth:
      profile: prod                       # a named ~/.aws profile
      access_key_id: AKIA...              # static keys (with secret_access_key)
      secret_access_key: ...
      session_token: ...                  # optional, for temporary keys
      role_arn: arn:aws:iam::123:role/X   # assume this role via STS
      external_id: ...                    # optional, paired with role_arn
      region: us-east-1                   # default region
      regions: [us-east-1, eu-west-1]     # regions services enumerate

Omit the block entirely to use the AWS default credential provider chain (env
vars, shared config, IRSA, ECS task role, EC2 instance profile) — the right
behavior in CI and in-cluster.

Resolution rules (mirroring the official AWS credential precedence):

* static ``access_key_id``/``secret_access_key`` -> exported as env for child
  ``aws`` calls (and used as the base identity for ``assume-role``);
* ``role_arn`` -> ``aws sts assume-role`` (using the static keys or ``profile``
  as the base), temporary credentials cached to expiry and exported as env;
* ``profile`` (no ``role_arn``) -> passed as ``--profile`` so the CLI resolves
  the profile (including any ``role_arn``/``source_profile`` it declares);
* nothing -> the default chain.
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .._env import child_env
from ..models import RegistryAuth

# runner(cmd, env) -> stdout. Injectable so tests never touch the real aws CLI.
CommandRunner = Callable[[list[str], "dict[str, str] | None"], str]

# Re-mint assumed-role creds before the 1h default STS expiry; ECR pull tokens
# live 12h, re-mint at 10h. Both are conservative.
_ASSUME_ROLE_TTL = 50 * 60
_ECR_TOKEN_TTL = 10 * 3600
_SESSION_NAME = "supplydrift-image-scanner"


class AwsAuthError(RuntimeError):
    """Raised when AWS credentials cannot be resolved."""


def _default_runner(cmd: list[str], env: dict[str, str] | None = None) -> str:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            # aws CLI needs PATH/HOME/AWS_* but not the platform secrets.
            env=child_env(env),
        )
    except FileNotFoundError as exc:
        raise AwsAuthError(f"'{cmd[0]}' not found on PATH (AWS connectors need the aws CLI)") from exc
    if completed.returncode != 0:
        raise AwsAuthError(f"{' '.join(cmd[:3])} failed: {completed.stderr.strip()}")
    return completed.stdout


def ecr_region_from_host(registry: str) -> str:
    """Extract the region from ``<acct>.dkr.ecr.<region>.amazonaws.com``."""
    parts = (registry or "").split(".")
    try:
        return parts[parts.index("ecr") + 1]
    except (ValueError, IndexError):
        return ""


@dataclass
class AwsSession:
    """Resolved AWS auth + region scope for a single source's ``aws_auth`` block."""

    profile: str = ""
    access_key_id: str = ""
    secret_access_key: str = ""
    session_token: str = ""
    role_arn: str = ""
    external_id: str = ""
    region: str = ""
    regions: list[str] = field(default_factory=list)
    runner: CommandRunner | None = None

    def __post_init__(self) -> None:
        self._run: CommandRunner = self.runner or _default_runner
        self._assumed: tuple[dict[str, str], float] | None = None
        self._ecr_cache: dict[str, tuple[RegistryAuth, float]] = {}

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None, runner: CommandRunner | None = None) -> "AwsSession":
        cfg = cfg or {}
        regions = [str(r) for r in (cfg.get("regions") or []) if r]
        region = str(cfg.get("region", "") or "")
        if not region and regions:
            region = regions[0]
        return cls(
            profile=str(cfg.get("profile", "") or ""),
            access_key_id=str(cfg.get("access_key_id", "") or ""),
            secret_access_key=str(cfg.get("secret_access_key", "") or ""),
            session_token=str(cfg.get("session_token", "") or ""),
            role_arn=str(cfg.get("role_arn", "") or ""),
            external_id=str(cfg.get("external_id", "") or ""),
            region=region,
            regions=regions,
            runner=runner,
        )

    # --- region scope ----------------------------------------------------- #
    def region_list(self) -> list[str]:
        """Regions a service connector should enumerate (may be empty)."""
        if self.regions:
            return list(self.regions)
        return [self.region] if self.region else []

    # --- credential resolution -------------------------------------------- #
    @property
    def _has_static_keys(self) -> bool:
        return bool(self.access_key_id and self.secret_access_key)

    def _base_env(self) -> dict[str, str]:
        if not self._has_static_keys:
            return {}
        env = {
            "AWS_ACCESS_KEY_ID": self.access_key_id,
            "AWS_SECRET_ACCESS_KEY": self.secret_access_key,
        }
        if self.session_token:
            env["AWS_SESSION_TOKEN"] = self.session_token
        return env

    def _base_args(self) -> list[str]:
        # Use the profile as the base identity only when no static keys are given.
        if self.profile and not self._has_static_keys:
            return ["--profile", self.profile]
        return []

    def _assume_role(self, now: float | None = None) -> dict[str, str]:
        now = time.time() if now is None else now
        if self._assumed and self._assumed[1] > now:
            return self._assumed[0]
        cmd = [
            "aws", "sts", "assume-role",
            "--role-arn", self.role_arn,
            "--role-session-name", _SESSION_NAME,
            "--output", "json",
        ]
        cmd += self._base_args()
        if self.region:
            cmd += ["--region", self.region]
        if self.external_id:
            cmd += ["--external-id", self.external_id]
        out = self._run(cmd, self._base_env() or None)
        try:
            creds = (json.loads(out or "{}") or {}).get("Credentials") or {}
        except json.JSONDecodeError as exc:
            raise AwsAuthError(f"could not parse 'aws sts assume-role' output: {exc}") from exc
        env = {
            "AWS_ACCESS_KEY_ID": creds.get("AccessKeyId", ""),
            "AWS_SECRET_ACCESS_KEY": creds.get("SecretAccessKey", ""),
            "AWS_SESSION_TOKEN": creds.get("SessionToken", ""),
        }
        if not env["AWS_ACCESS_KEY_ID"]:
            raise AwsAuthError(f"assume-role for {self.role_arn} returned no credentials")
        self._assumed = (env, now + _ASSUME_ROLE_TTL)
        return env

    def env(self, now: float | None = None) -> dict[str, str]:
        """Environment overrides for child ``aws`` calls ({} when using the default chain)."""
        if self.role_arn:
            return self._assume_role(now)
        return self._base_env()

    def cli_args(self, region: str | None = None) -> list[str]:
        """The ``aws`` command prefix (binary + global flags) for this session."""
        args = ["aws"]
        chosen = region or self.region
        if chosen:
            args += ["--region", chosen]
        # When assuming a role or using static keys, credentials flow via env,
        # so --profile would be wrong; only pass it for the pure-profile case.
        if not self.role_arn and self.profile and not self._has_static_keys:
            args += ["--profile", self.profile]
        return args

    def run(self, args: list[str], region: str | None = None, now: float | None = None) -> str:
        """Run ``aws <args>`` with this session's credentials; return stdout."""
        cmd = self.cli_args(region) + list(args)
        return self._run(cmd, self.env(now) or None)

    def run_json(self, args: list[str], region: str | None = None) -> Any:
        return json.loads(self.run(list(args) + ["--output", "json"], region=region) or "{}")

    # --- ECR pull token --------------------------------------------------- #
    def ecr_auth(self, registry: str, region: str | None = None, now: float | None = None) -> RegistryAuth:
        """Mint an ECR pull credential (username ``AWS``, 12h token), cached per region."""
        now = time.time() if now is None else now
        chosen = region or ecr_region_from_host(registry) or self.region
        if not chosen:
            regions = self.region_list()
            chosen = regions[0] if regions else "us-east-1"
        cached = self._ecr_cache.get(chosen)
        if cached and cached[1] > now:
            auth = cached[0]
            return RegistryAuth(username="AWS", password=auth.password, registry=registry, provider="ecr")
        password = self.run(["ecr", "get-login-password"], region=chosen, now=now).strip()
        if not password:
            raise AwsAuthError(f"'aws ecr get-login-password' returned no token for region {chosen}")
        auth = RegistryAuth(username="AWS", password=password, registry=registry, provider="ecr")
        self._ecr_cache[chosen] = (auth, now + _ECR_TOKEN_TTL)
        return auth
