"""Authentication primitives — pure crypto, stdlib only (no external deps).

Passwords are hashed with scrypt (memory-hard); API tokens are random and stored
as a sha256 hash (the plaintext is shown once at creation and never persisted).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

# scrypt work factors — n=2**14 (~16MB) is a sensible interactive-login cost.
_N = 2 ** 14
_R = 8
_P = 1
_DKLEN = 32

ROLES = ("admin", "member", "viewer")
TOKEN_SCOPES = ("runner", "ingest", "readonly")


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Return an encoded scrypt hash: ``scrypt$n$r$p$salt_hex$dk_hex``."""
    if not password:
        raise ValueError("password must not be empty")
    salt = salt if salt is not None else secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify of a password against an encoded scrypt hash."""
    try:
        scheme, n, r, p, salt_hex, dk_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = bytes.fromhex(dk_hex)
        dk = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p), dklen=len(expected),
        )
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


def new_token(prefix: str = "sdp") -> str:
    """A fresh opaque API token (the plaintext, shown once)."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_token(token: str) -> str:
    """Stable lookup hash for an API token (only the hash is stored)."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_session_id() -> str:
    return secrets.token_urlsafe(32)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(24)
