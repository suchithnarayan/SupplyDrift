"""Tests for the secret sanitizer (Task 5)."""
from __future__ import annotations

from github_inventory.sanitizer import REDACTED, sanitize


def test_aws_access_key_replaced():
    src = "credentials AWS_ACCESS=AKIAIOSFODNN7EXAMPLE end"
    out = sanitize(src)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert REDACTED in out
    # Surrounding text preserved
    assert "credentials" in out and "end" in out


def test_github_token_replaced():
    src = "export GH=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    out = sanitize(src)
    assert "ghp_aaaa" not in out
    assert REDACTED in out


def test_generic_assignment_keeps_key_redacts_value():
    src = 'api_key="abc123def456ghi789jkl012"'
    out = sanitize(src)
    assert "abc123def456ghi789jkl012" not in out
    # Key name is preserved so structure remains useful for the LLM.
    assert "api_key" in out
    assert REDACTED in out


def test_private_key_block_replaced():
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAA\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    out = sanitize(pem)
    assert "b3BlbnNzaC1rZXktdjEAAAAA" not in out
    assert REDACTED in out


def test_connection_string_password_replaced():
    src = "DB=mongodb://admin:supersecret123@host:27017/mydb"
    out = sanitize(src)
    assert "supersecret123" not in out
    assert "mongodb://admin:" in out  # scheme + user kept
    assert "@host:27017/mydb" in out  # host/path kept


def test_vendor_tokens_replaced():
    cases = [
        "github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "xoxb-123456789012-abcdefghijklmnop",
        "sk_live_abcdef0123456789ABCDEF",
        "AIzaSyА".replace("А", "A") + "0123456789012345678901234567890123",  # AIza + 35
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123",
        "npm_abcdefghijklmnopqrstuvwxyz0123456789",
        "pypi-AgEIcHlwaS5vcmcabcdefghijkl",
    ]
    for tok in cases:
        out = sanitize(f"value = {tok}")
        assert tok not in out, f"vendor token not redacted: {tok}"
        assert REDACTED in out


def test_jwt_replaced():
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
           ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
           ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    out = sanitize(f"Authorization: Bearer {jwt}")
    assert jwt not in out and REDACTED in out


def test_gcp_service_account_private_key_replaced():
    # GCP service-account JSON embeds the key with escaped \n sequences.
    src = '{"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBg\\n-----END PRIVATE KEY-----\\n"}'
    out = sanitize(src)
    assert "MIIEvQIBADANBg" not in out and REDACTED in out


def test_aws_secret_access_key_assignment_redacted():
    src = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    out = sanitize(src)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in out and REDACTED in out


def test_no_secrets_no_change():
    src = "curl https://example.com/install.sh | bash"
    assert sanitize(src) == src


def test_empty_input():
    assert sanitize("") == ""
