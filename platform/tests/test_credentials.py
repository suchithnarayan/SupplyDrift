"""Stored connector credentials: encrypted at rest, write-only, served only to runners."""
from __future__ import annotations

import crypto
import pytest


def _key(monkeypatch):
    monkeypatch.setenv("SUPPLYDRIFT_SECRET_KEY", crypto.generate_key())


def test_crypto_roundtrip(monkeypatch):
    _key(monkeypatch)
    ct = crypto.encrypt("s3cret")
    assert ct != "s3cret" and crypto.decrypt(ct) == "s3cret"


def test_crypto_requires_key(monkeypatch):
    monkeypatch.delenv("SUPPLYDRIFT_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        crypto.encrypt("x")
    assert crypto.decrypt("anything") is None  # missing key -> degrade, not crash


def _dh(store, password="p@ss", username="u"):
    return store.save_connector({
        "name": "DH", "source_type": "dockerhub",
        "connection": {"namespaces": ["a"], "auth": {"username": username, "password": password}},
    })


def test_secret_encrypted_and_not_leaked(empty_store, monkeypatch):
    _key(monkeypatch)
    s = empty_store
    c = _dh(s)
    # config keeps the username but NEVER the password
    assert c["config"]["connection"]["auth"]["username"] == "u"
    assert "password" not in c["config"]["connection"].get("auth", {})
    # the UI sees only which fields are configured, not the value
    assert c["secrets_configured"] == ["password"]
    assert s.list_connectors()[0]["secrets_configured"] == ["password"]
    # stored ciphertext is not the plaintext
    with s.connect() as conn:
        ct = conn.execute("SELECT ciphertext FROM connector_secrets WHERE connector_id = ?",
                          (c["id"],)).fetchone()["ciphertext"]
    assert "p@ss" not in ct


def test_scanner_config_resolves_static_for_runners(empty_store, monkeypatch):
    _key(monkeypatch)
    s = empty_store
    _dh(s)
    # Runner plane (include_secrets=True): real decrypted credentials.
    reg = s.scanner_config(include_secrets=True)["registries"][0]
    assert reg["connection"]["auth"]["password"] == "p@ss"
    assert reg["connection"]["auth"]["provider"] == "static"


def test_scanner_config_masks_secrets_by_default(empty_store, monkeypatch):
    _key(monkeypatch)
    s = empty_store
    _dh(s)
    # Default / human plane: structure preserved, secret VALUES masked.
    reg = s.scanner_config()["registries"][0]
    auth = reg["connection"]["auth"]
    assert "password" in auth and auth["password"] == "***"  # name kept, value hidden
    assert auth["username"] == "u"  # non-secret field still visible
    assert auth["provider"] == "static"


def test_scanner_config_scopes_secrets_to_one_connector(empty_store, monkeypatch):
    # A runner scoping the request to a connector_id gets the real secret only for that
    # connector; every other connector's secret stays masked (SD-03 least-privilege).
    _key(monkeypatch)
    s = empty_store
    a = s.save_connector({"name": "DH-A", "source_type": "dockerhub",
                          "connection": {"namespaces": ["a"], "auth": {"username": "ua", "password": "secretA"}}})
    b = s.save_connector({"name": "DH-B", "source_type": "dockerhub",
                          "connection": {"namespaces": ["b"], "auth": {"username": "ub", "password": "secretB"}}})
    regs = {r["connector_id"]: r["connection"]["auth"]
            for r in s.scanner_config(include_secrets=True, only_connector_id=a["id"])["registries"]}
    assert regs[a["id"]]["password"] == "secretA"   # requested connector: real value
    assert regs[b["id"]]["password"] == "***"        # other connector: masked
    # unscoped (legacy) still hands a runner all real secrets
    regs_all = {r["connector_id"]: r["connection"]["auth"]
                for r in s.scanner_config(include_secrets=True)["registries"]}
    assert regs_all[b["id"]]["password"] == "secretB"


def test_secret_like_connector_fields_are_rejected(empty_store, monkeypatch):
    _key(monkeypatch)
    with pytest.raises(ValueError, match="secret-like connector fields"):
        empty_store.save_connector({
            "name": "AWS", "source_type": "ecr",
            "connection": {"aws_auth": {"profile": "prod", "secret_access_key": "not-safe"}},
        })
    with pytest.raises(ValueError, match="secret-like connector fields"):
        empty_store.save_connector({
            "name": "GH", "source_type": "github",
            "connection": {"auth": {"client_secret": "not-safe"}},
        })


def test_auth_env_references_remain_visible_config(empty_store, monkeypatch):
    _key(monkeypatch)
    c = empty_store.save_connector({
        "name": "GH", "source_type": "github",
        "connection": {"auth": {"provider": "env", "token_env": "GH_PAT"}},
    })
    assert c["config"]["connection"]["auth"]["token_env"] == "GH_PAT"
    assert c["secrets_configured"] == []


def test_blank_secret_keeps_existing(empty_store, monkeypatch):
    _key(monkeypatch)
    s = empty_store
    c = _dh(s, password="first")
    s.save_connector({"name": "DH", "source_type": "dockerhub",
                      "connection": {"auth": {"username": "u2", "password": ""}}}, c["id"])
    assert s.get_connector_secrets(c["id"])["password"] == "first"  # not overwritten


def test_masked_secret_roundtrip_keeps_existing(empty_store, monkeypatch):
    # Re-submitting the "***" mask the scanner-config API echoes must NOT clobber the
    # stored credential with the mask (SD-13).
    _key(monkeypatch)
    s = empty_store
    c = _dh(s, password="first")
    s.save_connector({"name": "DH", "source_type": "dockerhub",
                      "connection": {"auth": {"username": "u2", "password": "***"}}}, c["id"])
    assert s.get_connector_secrets(c["id"])["password"] == "first"  # mask ignored, real secret kept


def test_storing_secret_without_key_errors(empty_store, monkeypatch):
    monkeypatch.delenv("SUPPLYDRIFT_SECRET_KEY", raising=False)
    with pytest.raises(ValueError):
        empty_store.save_connector({"name": "DH", "source_type": "dockerhub",
                                    "connection": {"auth": {"password": "p"}}})
