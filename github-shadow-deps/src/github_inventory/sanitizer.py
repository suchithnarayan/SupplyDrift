"""
Pre-processing filter to strip secrets from code before sending to an LLM.

Secrets must NEVER leave the local machine. This is applied to every snippet
before it is forwarded to the AI analyzer or enrichment paths.

Patterns removed (replaced with <REDACTED_SECRET>):
- AWS access keys (AKIA...)
- GitHub tokens (classic gh[pousr]_... and fine-grained github_pat_...)
- Well-known vendor tokens: JWTs, Slack, Stripe, Google API keys, OpenAI, npm, PyPI
- Generic API keys / tokens / passwords in assignment context (covers AWS secret
  access keys, GCP/Azure client secrets, etc. when written as key = value)
- Private key blocks (RSA / EC / OPENSSH / DSA / PGP), incl. JSON-escaped (\n) form
- Connection strings with passwords (mongodb://, postgres://, mysql://, redis://, amqp://)

NOTE: this is best-effort defense-in-depth. The AI path is opt-in (--ai/--enrich)
and we deliberately avoid a broad high-entropy catch-all that would mangle ordinary
code (hashes, base64 blobs) and degrade analysis. Add specific patterns over time.
"""
from __future__ import annotations

import re

REDACTED = "<REDACTED_SECRET>"

# Whole-match secrets: the entire match is replaced.
_WHOLE_MATCH_PATTERNS: list[re.Pattern] = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),                # GitHub classic token
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),              # GitHub fine-grained PAT
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),              # Slack token
    re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{16,}"),           # Stripe live secret/restricted
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                    # Google API key
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),          # OpenAI API key
    re.compile(r"npm_[A-Za-z0-9]{36}"),                       # npm automation token
    re.compile(r"pypi-[A-Za-z0-9_\-]{16,}"),                  # PyPI API token
    # PEM-style private key blocks; [\s\S] also spans JSON-escaped "\n" sequences.
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        r"[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    ),
]

# Generic high-entropy assignments: api_key="...", token=..., secret: ..., etc.
# Captures the value (group "v") so we replace just the secret, not the key name.
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?P<k>api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret"
    r"|token|password|passwd|pwd|secret)"
    r"\s*[=:]\s*['\"]?(?P<v>[A-Za-z0-9/+=_\-]{20,})['\"]?"
)

# Connection strings with an embedded password.
_CONN_PATTERN = re.compile(
    r"(?i)(?P<scheme>mongodb|mongodb\+srv|postgres|postgresql|mysql|redis|amqp)://"
    r"(?P<user>[^:\s/@]+):(?P<pw>[^@\s/]+)@"
)


def sanitize(text: str) -> str:
    """Replace any matched secret with <REDACTED_SECRET>.

    Preserves the surrounding code so the LLM still sees structure
    (variable names, key names, URL hosts) but never the secret value.
    """
    if not text:
        return text

    out = text

    for pat in _WHOLE_MATCH_PATTERNS:
        out = pat.sub(REDACTED, out)

    # Generic assignment: keep the key, redact the value.
    out = _ASSIGNMENT_PATTERN.sub(lambda m: f"{m.group('k')}={REDACTED}", out)

    # Connection strings: keep scheme + user, redact password.
    out = _CONN_PATTERN.sub(lambda m: f"{m.group('scheme')}://{m.group('user')}:{REDACTED}@", out)

    return out
