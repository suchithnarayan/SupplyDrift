"""Fail-safe redaction for findings crossing a trust boundary.

Scanners inspect attacker-controlled repositories, so every output path must
treat finding text as potentially credential-bearing.  This module is the
single redaction implementation used by models, reporters, enrichment, and
platform synchronization.
"""
from __future__ import annotations

import re
from typing import Any

from github_inventory.sanitizer import REDACTED as SANITIZER_REDACTED
from github_inventory.sanitizer import sanitize

REDACTED = "[REDACTED]"

_URL_USERINFO_RE = re.compile(
    r"(?P<scheme>\b(?:https?|git\+https?)://)(?P<userinfo>[^/@\s]+)@",
    re.IGNORECASE,
)
_NPM_AUTH_TOKEN_RE = re.compile(
    r"(?P<prefix>//[^\s]+/:_authToken\s*=\s*)(?P<value>[^\s'\"]+)",
    re.IGNORECASE,
)
_SECRET_QUERY_RE = re.compile(
    r"(?P<prefix>[?&](?:access[_-]?token|auth[_-]?token|api[_-]?key|"
    r"client[_-]?secret|password|passwd|secret|signature|sig|token|"
    r"x-amz-credential|x-amz-security-token|x-amz-signature)=)"
    r"(?P<value>[^&#\s'\"<>]+)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>\b(?:_authToken|access[_-]?token|auth[_-]?token|api[_-]?key|"
    r"client[_-]?secret|password|passwd|secret|secret[_-]?access[_-]?key|"
    r"token)\b\s*(?:=|:)\s*)"
    r"(?P<quote>['\"]?)(?P<value>\[REDACTED\]|[^\s,'\"}\]]+)(?P=quote)",
    re.IGNORECASE,
)
_AUTHORIZATION_RE = re.compile(
    r"(?P<prefix>\bAuthorization\s*:\s*(?:Basic|Bearer)\s+)(?P<value>[^\s'\"]+)",
    re.IGNORECASE,
)


def redact_text(value: str) -> str:
    """Return an idempotently redacted representation of untrusted text."""
    if not value:
        return value

    # Reuse the broader AI-boundary sanitizer for bare, well-known credential
    # formats (GitHub, AWS, npm, PyPI, JWT, private keys, and connection
    # strings), then apply output-specific contextual rules below.  Normalize
    # both layers to one stable marker so repeated boundary checks are
    # idempotent.
    value = sanitize(value).replace(SANITIZER_REDACTED, REDACTED)
    value = _URL_USERINFO_RE.sub(
        lambda match: f"{match.group('scheme')}{REDACTED}@",
        value,
    )
    value = _NPM_AUTH_TOKEN_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}",
        value,
    )
    value = _SECRET_QUERY_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}",
        value,
    )
    value = _SECRET_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}",
        value,
    )
    return _AUTHORIZATION_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}",
        value,
    )


def redact_value(value: Any) -> Any:
    """Recursively redact strings without mutating the supplied value."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value
