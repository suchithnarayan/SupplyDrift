"""Application-level encryption for stored connector credentials.

Secrets are encrypted with Fernet (AES-128-CBC + HMAC) under a key supplied via
``SUPPLYDRIFT_SECRET_KEY`` — kept OUT of the database, so a DB dump alone cannot
decrypt them. The key is REQUIRED to store a credential; without it, storing fails
loudly (read returns None so the app degrades instead of crashing).
"""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken


def generate_key() -> str:
    """A fresh url-safe base64 Fernet key (for `SUPPLYDRIFT_SECRET_KEY`)."""
    return Fernet.generate_key().decode()


def key_present() -> bool:
    return bool(os.environ.get("SUPPLYDRIFT_SECRET_KEY"))


def _fernet() -> Fernet | None:
    key = os.environ.get("SUPPLYDRIFT_SECRET_KEY")
    if not key:
        return None
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            "SUPPLYDRIFT_SECRET_KEY is not a valid Fernet key — generate one with "
            "`python -c 'import crypto; print(crypto.generate_key())'`"
        ) from exc


def encrypt(plaintext: str) -> str:
    """Encrypt a secret. Raises if SUPPLYDRIFT_SECRET_KEY is unset."""
    f = _fernet()
    if f is None:
        raise RuntimeError("SUPPLYDRIFT_SECRET_KEY is required to store credentials")
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str | None:
    """Decrypt a secret, or None if the key is missing/wrong or the token is invalid."""
    f = _fernet()
    if f is None:
        return None
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        return None
