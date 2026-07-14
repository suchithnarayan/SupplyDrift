"""Child-process environment hardening.

Discovery helpers such as the AWS CLI and kubectl inherit much of the scanner's
environment by default. That environment carries the runner's platform bearer
token and the platform's credential-encryption key, neither of which those
helpers needs. Strip them before launching discovery commands. Syft and Grype
use the stricter per-invocation capability sandbox and a minimal allowlist.
"""
from __future__ import annotations

import os

# Secrets that must never leak into a child process's environment: the runner's
# platform bearer token and the platform's Fernet credential-encryption key.
SENSITIVE_ENV_VARS = ("SUPPLYDRIFT_RUNNER_TOKEN", "SUPPLYDRIFT_SECRET_KEY")


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """A copy of ``os.environ`` with the platform secrets removed.

    Everything else (PATH, HOME, AWS_*, DOCKER_CONFIG, ...) is preserved so the
    child tool still works. ``extra`` is merged on top for tool-specific vars.
    """
    env = {k: v for k, v in os.environ.items() if k not in SENSITIVE_ENV_VARS}
    if extra:
        env.update(extra)
    return env
