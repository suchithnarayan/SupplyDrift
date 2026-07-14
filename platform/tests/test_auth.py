"""Auth core: password hashing, users, sessions, API tokens, runner-token bootstrap."""
from __future__ import annotations

import auth
import pytest


# ── crypto primitives ───────────────────────────────────────────────────────
def test_password_hash_roundtrip():
    h = auth.hash_password("hunter2")
    assert h.startswith("scrypt$") and h != "hunter2"
    assert auth.verify_password("hunter2", h) is True
    assert auth.verify_password("wrong", h) is False
    # distinct salts -> distinct hashes for the same password
    assert auth.hash_password("hunter2") != h


def test_verify_password_rejects_garbage():
    assert auth.verify_password("x", "not-a-hash") is False


def test_token_hash_is_stable_and_opaque():
    t = auth.new_token()
    assert t.startswith("sdp_")
    assert auth.hash_token(t) == auth.hash_token(t) and auth.hash_token(t) != t


# ── users + login ───────────────────────────────────────────────────────────
def test_create_user_and_login(empty_store):
    s = empty_store
    u = s.create_user("Alice", "s3cret-pass", role="admin")
    assert u["username"] == "alice" and u["role"] == "admin" and "password_hash" not in u
    assert s.verify_login("alice", "s3cret-pass")["id"] == u["id"]
    assert s.verify_login("alice", "nope") is None
    assert s.verify_login("ghost", "x") is None
    with pytest.raises(ValueError):
        s.create_user("alice", "dup-pass-123")          # duplicate username
    with pytest.raises(ValueError):
        s.create_user("bob", "x-pass-1234", role="root")  # invalid role


def test_disabled_user_cannot_login(empty_store):
    s = empty_store
    u = s.create_user("bob", "pw-123456")
    s.update_user(u["id"], disabled=True)
    assert s.verify_login("bob", "pw-123456") is None


def test_password_policy_enforced_in_store(empty_store):
    """The ≥8-char minimum lives in the Store, not just the UI/change-password
    route, so direct API/bootstrap callers can't create weak passwords."""
    s = empty_store
    with pytest.raises(ValueError, match="at least 8"):
        s.create_user("shorty", "seven77")               # 7 chars
    with pytest.raises(ValueError, match="at least 8"):
        s.bootstrap_admin("root", "tiny")
    u = s.create_user("frank", "long-enough-pw")
    with pytest.raises(ValueError, match="at least 8"):
        s.update_user(u["id"], password="short")
    # non-password updates are unaffected
    assert s.update_user(u["id"], role="viewer")["role"] == "viewer"


def test_unknown_user_login_burns_decoy_hash(empty_store):
    """A miss must burn the same scrypt work as a hit (no username enumeration
    via response timing): the decoy hash is computed and cached on first miss."""
    import app as appmod

    s = empty_store
    assert s.verify_login("ghost", "whatever-pw") is None
    assert appmod.Store._decoy_hash is not None
    assert appmod.Store._decoy_hash.startswith("scrypt$")


def test_bootstrap_admin_only_on_empty(empty_store):
    s = empty_store
    assert s.count_users() == 0
    admin = s.bootstrap_admin("root", "root-pass-123")
    assert admin["role"] == "admin"
    assert s.bootstrap_admin("root2", "root-pass-123") is None  # no-op once a user exists
    assert s.count_users() == 1


# ── sessions ────────────────────────────────────────────────────────────────
def test_session_lifecycle(empty_store):
    s = empty_store
    u = s.create_user("carol", "pw-123456")
    sess = s.create_session(u["id"])
    assert sess["session_id"] and sess["csrf_token"]
    p = s.get_session_principal(sess["session_id"])
    assert p["user"]["id"] == u["id"] and p["csrf_token"] == sess["csrf_token"]
    s.delete_session(sess["session_id"])
    assert s.get_session_principal(sess["session_id"]) is None
    assert s.get_session_principal("bogus") is None


def test_expired_session_is_rejected(empty_store):
    s = empty_store
    u = s.create_user("dave", "pw-123456")
    sess = s.create_session(u["id"])
    with s.connect() as conn:  # force-expire it
        conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (sess["session_id"],))
    assert s.get_session_principal(sess["session_id"]) is None


def test_disabling_user_revokes_sessions(empty_store):
    s = empty_store
    u = s.create_user("erin", "pw-123456")
    sess = s.create_session(u["id"])
    s.update_user(u["id"], disabled=True)
    assert s.get_session_principal(sess["session_id"]) is None


# ── API tokens ──────────────────────────────────────────────────────────────
def test_token_create_resolve_revoke(empty_store):
    s = empty_store
    tok = s.create_token("ci-readonly", "readonly", created_by="admin")
    assert tok["token"].startswith("sdp_") and tok["scope"] == "readonly"
    resolved = s.resolve_token(tok["token"])
    assert resolved["scope"] == "readonly" and resolved["id"] == tok["id"]
    assert s.resolve_token("sdp_garbage") is None
    assert s.revoke_token(tok["id"]) is True
    assert s.resolve_token(tok["token"]) is None          # revoked -> dead
    assert [t["id"] for t in s.list_tokens()] == [tok["id"]]
    with pytest.raises(ValueError):
        s.create_token("x", "superuser")                   # invalid scope


def test_ensure_runner_token_idempotent(empty_store):
    s = empty_store
    val = auth.new_token()
    s.ensure_runner_token(val)
    s.ensure_runner_token(val)                              # idempotent — no duplicate
    toks = [t for t in s.list_tokens() if t["scope"] == "runner"]
    assert len(toks) == 1 and toks[0]["name"] == "bundled-runners"
    assert s.resolve_token(val)["scope"] == "runner"
    # a revoked bundled token is re-activated on next ensure (restart heals it)
    s.revoke_token(toks[0]["id"])
    s.ensure_runner_token(val)
    assert s.resolve_token(val)["scope"] == "runner"
