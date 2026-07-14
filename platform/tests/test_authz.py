"""Auth enforcement over HTTP: sessions, CSRF, roles, bearer tokens, public routes."""
from __future__ import annotations

import authz
import pytest


@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    """An auth-ENABLED TestClient + store + a seeded admin. (Default suite runs disabled.)"""
    monkeypatch.setenv("SUPPLYDRIFT_AUTH", "enabled")
    monkeypatch.setenv("SUPPLYDRIFT_INSECURE", "1")  # TestClient is http -> non-Secure cookies
    # Login throttle is DB-backed now; each test gets a fresh DB so it's isolated.
    from fastapi.testclient import TestClient

    import app as appmod
    import server

    s = appmod.Store(tmp_path / "auth.db")
    s.ingest(appmod.demo_payload())
    s.create_user("admin", "admin-pass-123", role="admin")
    return TestClient(server.create_app(s)), s


def _login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    return r


CONNECTOR = {"name": "X", "source_type": "dockerhub", "connection": {"namespaces": ["a"]}}


# ── public + unauthenticated ────────────────────────────────────────────────
def test_health_is_public(auth_client):
    client, _ = auth_client
    assert client.get("/api/health").status_code == 200


def test_unauthenticated_is_401(auth_client):
    client, _ = auth_client
    assert client.get("/api/summary").status_code == 401
    assert client.post("/api/connectors", json=CONNECTOR).status_code == 401


# ── session login flow ──────────────────────────────────────────────────────
def test_login_then_read(auth_client):
    client, _ = auth_client
    r = _login(client, "admin", "admin-pass-123")
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin" and r.json()["csrf_token"]
    assert client.get("/api/summary").status_code == 200          # cookie carries the session
    assert client.get("/api/auth/me").json()["role"] == "admin"


def test_bad_password_and_throttle(auth_client):
    client, _ = auth_client
    for _ in range(5):
        assert _login(client, "admin", "wrong").status_code == 401
    assert _login(client, "admin", "admin-pass-123").status_code == 429  # throttled


def test_login_throttle_is_per_username_and_resets(auth_client):
    _, store = auth_client
    for _ in range(store.LOGIN_MAX_FAILS):
        assert store.login_throttled("admin") is False
        store.record_login_failure("admin")
    assert store.login_throttled("admin") is True       # locked after N fails
    assert store.login_throttled("someone-else") is False  # other accounts unaffected
    store.clear_login_attempts("admin")                 # a success clears it
    assert store.login_throttled("admin") is False


def test_login_ip_throttle_key_and_disable(auth_client):
    # The per-IP throttle reuses the attempts table under an "ip:" key with its own,
    # configurable cap (SD-07). max_fails=0 disables the limit.
    _, store = auth_client
    for _ in range(3):
        store.record_login_failure("ip:203.0.113.9")
    assert store.login_throttled("ip:203.0.113.9", max_fails=3) is True
    assert store.login_throttled("ip:203.0.113.9", max_fails=10) is False
    assert store.login_throttled("ip:203.0.113.9", max_fails=0) is False


def test_login_rejects_oversized_body(auth_client):
    # A >64KB auth body must be handled safely (not buffered unbounded / 500) — SD-08.
    client, _ = auth_client
    r = _login(client, "x" * (70 * 1024), "y")
    assert r.status_code in (400, 401, 429)  # treated as empty creds, never a crash


# ── CSRF on cookie mutations ────────────────────────────────────────────────
def test_csrf_required_for_cookie_mutation(auth_client):
    client, _ = auth_client
    csrf = _login(client, "admin", "admin-pass-123").json()["csrf_token"]
    # cookie present but no CSRF header -> 403
    assert client.post("/api/connectors", json=CONNECTOR).status_code == 403
    # with the CSRF header -> allowed through (201)
    r = client.post("/api/connectors", json=CONNECTOR, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201


# ── role enforcement ────────────────────────────────────────────────────────
def test_viewer_can_read_not_write(auth_client):
    client, store = auth_client
    store.create_user("val", "viewer-pass-1", role="viewer")
    csrf = _login(client, "val", "viewer-pass-1").json()["csrf_token"]
    assert client.get("/api/summary").status_code == 200
    assert client.post("/api/connectors", json=CONNECTOR, headers={"X-CSRF-Token": csrf}).status_code == 403


def test_member_cannot_manage_users(auth_client):
    client, store = auth_client
    store.create_user("mem", "member-pass-1", role="member")
    _login(client, "mem", "member-pass-1")
    assert client.get("/api/admin/users").status_code == 403   # admin-only
    # but an admin can
    client.post("/api/auth/logout")
    _login(client, "admin", "admin-pass-123")
    assert client.get("/api/admin/users").status_code == 200


# ── bearer tokens (machines) ────────────────────────────────────────────────
def test_runner_token_can_claim_readonly_cannot(auth_client):
    client, store = auth_client
    runner = store.create_token("r", "runner")["token"]
    readonly = store.create_token("ro", "readonly")["token"]
    claim = {"job_type": "image", "runner_id": "t"}

    # runner scope -> queue allowed (no CSRF needed for bearer); empty queue -> null/200
    assert client.post("/api/scan/runs/claim", json=claim,
                       headers={"Authorization": f"Bearer {runner}"}).status_code == 200
    # readonly scope -> can read, cannot claim
    assert client.get("/api/summary", headers={"Authorization": f"Bearer {readonly}"}).status_code == 200
    assert client.post("/api/scan/runs/claim", json=claim,
                       headers={"Authorization": f"Bearer {readonly}"}).status_code == 403
    # garbage bearer -> 401
    assert client.get("/api/summary", headers={"Authorization": "Bearer nope"}).status_code == 401


# ── scanner config secret exposure (C1) ─────────────────────────────────────
def test_scanner_config_secrets_only_for_runners(auth_client, monkeypatch):
    import crypto
    client, store = auth_client
    monkeypatch.setenv("SUPPLYDRIFT_SECRET_KEY", crypto.generate_key())
    store.save_connector({
        "name": "DH", "source_type": "dockerhub",
        "connection": {"namespaces": ["a"], "auth": {"username": "u", "password": "p@ss"}},
    })

    # human admin has QUEUE, but browser sessions must still receive masked values
    _login(client, "admin", "admin-pass-123")
    auth = client.get("/api/scanner/config").json()["registries"][0]["connection"]["auth"]
    assert auth["password"] == "***" and auth["username"] == "u"
    client.post("/api/auth/logout")

    # human operator (member, has OPERATE) -> reaches the route but values are masked
    store.create_user("mem", "member-pass-1", role="member")
    _login(client, "mem", "member-pass-1")
    auth = client.get("/api/scanner/config").json()["registries"][0]["connection"]["auth"]
    assert auth["password"] == "***" and auth["username"] == "u"
    client.post("/api/auth/logout")

    # runner token (QUEUE) -> real decrypted secret
    runner = store.create_token("r", "runner")["token"]
    auth = client.get("/api/scanner/config", headers={"Authorization": f"Bearer {runner}"}
                      ).json()["registries"][0]["connection"]["auth"]
    assert auth["password"] == "p@ss"

    # readonly token has neither QUEUE nor OPERATE -> blocked entirely
    ro = store.create_token("ro", "readonly")["token"]
    assert client.get("/api/scanner/config",
                      headers={"Authorization": f"Bearer {ro}"}).status_code == 403


def test_member_cannot_mint_runner_token_via_api(auth_client):
    client, store = auth_client
    store.create_user("mem", "member-pass-1", role="member")
    csrf = _login(client, "mem", "member-pass-1").json()["csrf_token"]

    blocked = client.post("/api/admin/tokens", json={"name": "r", "scope": "runner"},
                          headers={"X-CSRF-Token": csrf})
    assert blocked.status_code == 403

    allowed = client.post("/api/admin/tokens", json={"name": "ro", "scope": "readonly"},
                          headers={"X-CSRF-Token": csrf})
    assert allowed.status_code == 201 and allowed.json()["scope"] == "readonly"


def test_admin_can_mint_token_via_api(auth_client):
    client, _ = auth_client
    csrf = _login(client, "admin", "admin-pass-123").json()["csrf_token"]
    r = client.post("/api/admin/tokens", json={"name": "ci", "scope": "readonly"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201 and r.json()["token"].startswith("sdp_") and r.json()["scope"] == "readonly"


# ── auth-disabled rail: public peers are refused ────────────────────────────
def test_client_is_remote_classification():
    from types import SimpleNamespace as NS

    def req(host):
        return NS(client=NS(host=host))

    assert authz._client_is_remote(req("8.8.8.8")) is True                # public v4
    assert authz._client_is_remote(req("2001:4860:4860::8888")) is True   # public v6
    assert authz._client_is_remote(req("::ffff:8.8.8.8")) is True         # v4-mapped v6
    assert authz._client_is_remote(req("127.0.0.1")) is False             # loopback
    assert authz._client_is_remote(req("::1")) is False
    assert authz._client_is_remote(req("172.18.0.5")) is False            # compose bridge
    assert authz._client_is_remote(req("192.168.1.10")) is False          # RFC1918
    assert authz._client_is_remote(req("testclient")) is False            # ASGI harness
    assert authz._client_is_remote(NS(client=None)) is False


def test_auth_disabled_refuses_public_peers(fastapi_client, monkeypatch):
    """The suite runs auth-disabled (conftest); a public peer must get 403 in
    that mode unless the operator set the explicit override env var."""
    client, _ = fastapi_client
    monkeypatch.setattr(authz, "_client_is_remote", lambda _r: True)
    assert client.get("/api/summary").status_code == 403
    monkeypatch.setenv("SUPPLYDRIFT_I_UNDERSTAND_AUTH_DISABLED", "1")
    assert client.get("/api/summary").status_code == 200
