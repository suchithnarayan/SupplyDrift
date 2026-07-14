"""Authorization layer for the SupplyDrift API.

Two planes resolve to one Principal:
  * humans  -> httpOnly session cookie (+ CSRF token on mutations)
  * machines-> Authorization: Bearer <api token>

A single HTTP middleware resolves the principal, enforces a path->capability
policy, and runs CSRF for cookie-based mutations. ``SUPPLYDRIFT_AUTH=disabled``
bypasses everything (returns a synthetic admin) for trusted local/dev + the test
suite. The auth routes (login/logout/me, admin users + tokens, health) live here.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import secrets
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import auth

log = logging.getLogger("supplydrift.auth")

# ── capabilities ────────────────────────────────────────────────────────────
READ, OPERATE, ADMIN, QUEUE, INGEST = "read", "operate", "admin", "queue", "ingest"

ROLE_CAPS: dict[str, set[str]] = {
    "admin": {READ, OPERATE, ADMIN, QUEUE, INGEST},
    "member": {READ, OPERATE},
    "viewer": {READ},
}
SCOPE_CAPS: dict[str, set[str]] = {
    "runner": {QUEUE, INGEST},
    "ingest": {INGEST},
    "readonly": {READ},
}

SESSION_COOKIE = "sd_session"
CSRF_HEADER = "x-csrf-token"
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def auth_enabled() -> bool:
    return os.environ.get("SUPPLYDRIFT_AUTH", "enabled").strip().lower() != "disabled"


def _secure_cookies() -> bool:
    return os.environ.get("SUPPLYDRIFT_INSECURE", "").strip() != "1"


def _client_is_remote(request: Request) -> bool:
    """True only for a demonstrably PUBLIC peer address.

    Loopback is first-class local. Private/link-local peers are allowed because
    the bundled compose runners reach the platform over the compose bridge
    network in auth-disabled dev mode (LAN exposure is already gated by
    BIND_ADDR defaulting to 127.0.0.1 and run.py's non-loopback refusal). Non-IP
    peers (ASGI test harnesses, unix sockets) count as local.
    """
    host = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return bool(addr.is_global)


def cors_origins() -> list[str]:
    """Locked CORS origins (replaces the old wildcard). In production only the
    configured public URL is allowed (the SPA is served same-origin, so it needs
    no CORS); the localhost dev ports (incl. the Vite server on :5173) are added
    only in dev mode (SUPPLYDRIFT_INSECURE=1)."""
    pub = os.environ.get("SUPPLYDRIFT_PUBLIC_URL", "http://localhost:8765").rstrip("/")
    origins = {pub}
    if not _secure_cookies():  # dev mode
        origins |= {"http://localhost:8765", "http://127.0.0.1:8765",
                    "http://localhost:5173", "http://127.0.0.1:5173"}
    return list(origins)


class Principal:
    def __init__(self, kind: str, caps: set[str], *, id=None, username=None,
                 role=None, scope=None, csrf=None):
        self.kind = kind
        self.caps = caps
        self.id = id
        self.username = username
        self.role = role
        self.scope = scope
        self.csrf = csrf

    @property
    def is_user(self) -> bool:
        return self.kind in ("user", "system")


def _system_principal() -> Principal:
    return Principal("system", set(ROLE_CAPS["admin"]), username="system", role="admin")


def resolve_principal(store, request: Request) -> Principal | None:
    """Bearer token -> token principal; else session cookie -> user principal; else None."""
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        tok = store.resolve_token(header[7:].strip())
        if tok:
            return Principal("token", set(SCOPE_CAPS.get(tok["scope"], set())),
                             id=tok["id"], scope=tok["scope"])
        return None
    sid = request.cookies.get(SESSION_COOKIE)
    if sid:
        p = store.get_session_principal(sid)
        if p:
            u = p["user"]
            return Principal("user", set(ROLE_CAPS.get(u["role"], set())), id=u["id"],
                             username=u["username"], role=u["role"], csrf=p["csrf_token"])
    return None


def required_caps(method: str, path: str):
    """Return None (public), "authed" (any principal), or a set of caps (any-of)."""
    if not path.startswith("/api/"):
        return None  # static SPA assets / index
    if path in ("/api/health", "/api/auth/login", "/api/auth/logout"):
        return None  # logout is public so it always clears the cookie
    if path in ("/api/auth/me", "/api/auth/change-password"):
        return "authed"
    # machine plane (queue + ingest)
    if path == "/api/scan/runs/claim":
        return {QUEUE}
    if path.startswith("/api/scan/runs/") and path.endswith("/complete"):
        return {QUEUE}
    if path in ("/api/malware/cursor", "/api/malware/match"):
        return {QUEUE}
    if path == "/api/ingest" or path.startswith("/api/sync/"):
        return {INGEST}
    if path == "/api/scanner/config":
        return {QUEUE, OPERATE}  # runner token OR a human operator
    # admin
    if path.startswith("/api/demo/"):
        return {ADMIN}  # destructive dev-only routes (reset wipes data) — admin even when demo is on
    if path.startswith("/api/admin/users"):
        return {ADMIN}
    if path.startswith("/api/admin/tokens"):
        return {OPERATE}  # member+ self-service; "revoke any" enforced in the handler
    # default: reads need READ, mutations need OPERATE
    return {READ} if method == "GET" else {OPERATE}


# ── startup bootstrap ───────────────────────────────────────────────────────
def _ensure_runner_token_value() -> str | None:
    """The shared runner token: explicit env wins; else read-or-generate the file on
    the shared volume so co-located runners authenticate with zero human steps."""
    env_tok = os.environ.get("SUPPLYDRIFT_RUNNER_TOKEN")
    if env_tok:
        return env_tok.strip()
    path = Path(os.environ.get("SUPPLYDRIFT_RUNNER_TOKEN_FILE", "/run/supplydrift/runner.token"))
    try:
        if path.exists():
            return path.read_text(encoding="utf-8").strip() or None
        path.parent.mkdir(parents=True, exist_ok=True)
        tok = auth.new_token("sdr")
        path.write_text(tok, encoding="utf-8")
        os.chmod(path, 0o600)
        log.info("generated bundled runner token at %s", path)
        return tok
    except OSError as exc:
        log.warning("no shared runner-token volume (%s); set SUPPLYDRIFT_RUNNER_TOKEN for runners", exc)
        return None


def bootstrap(store) -> None:
    """Seed the env-var admin on a fresh install and register the bundled runner token."""
    if not auth_enabled():
        log.warning("SUPPLYDRIFT_AUTH=disabled — the API is UNAUTHENTICATED")
        return
    if store.count_users() == 0:
        admin_user = os.environ.get("SUPPLYDRIFT_ADMIN_USER")
        admin_pw = os.environ.get("SUPPLYDRIFT_ADMIN_PASSWORD")
        if admin_user and admin_pw:
            try:
                store.bootstrap_admin(admin_user, admin_pw)
                log.info("seeded admin user '%s' from SUPPLYDRIFT_ADMIN_*", admin_user.lower())
            except ValueError as exc:
                # e.g. password below the Store's minimum length: keep the platform
                # up (401s until fixed, same as the unset case) instead of crashing.
                log.error("cannot seed admin from SUPPLYDRIFT_ADMIN_*: %s — fix and restart", exc)
        else:
            log.error("AUTH on but NO users exist and SUPPLYDRIFT_ADMIN_USER/PASSWORD are unset "
                      "— set them and restart to log in")
    token = _ensure_runner_token_value()
    if token:
        store.ensure_runner_token(token)


# ── install: middleware + auth routes ───────────────────────────────────────
# Auth-route bodies (login, change-password) are tiny; cap the read so an
# unauthenticated caller can't force large-body memory pressure on /api/auth/*
# (the ingest routes have their own, larger cap in server.py).
_AUTH_MAX_BODY_BYTES = 64 * 1024


async def _json(request: Request) -> dict:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > _AUTH_MAX_BODY_BYTES:
        return {}
    total = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        total += len(chunk)
        if total > _AUTH_MAX_BODY_BYTES:
            return {}  # oversized -> treat as empty; auth then fails safely
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return {}


def install_auth(api: FastAPI, store) -> None:
    @api.middleware("http")
    async def _enforce(request: Request, call_next):
        if not auth_enabled():
            # Same rail as run.py's non-loopback refusal, but enforced per request
            # so a direct `uvicorn server:api` start on a public interface is also
            # covered: with auth off, never serve a public-internet peer unless the
            # operator explicitly opted in.
            if (_client_is_remote(request)
                    and os.environ.get("SUPPLYDRIFT_I_UNDERSTAND_AUTH_DISABLED") != "1"):
                return JSONResponse(status_code=403, content={
                    "error": "SUPPLYDRIFT_AUTH=disabled does not serve public addresses; "
                             "enable auth or set SUPPLYDRIFT_I_UNDERSTAND_AUTH_DISABLED=1"})
            request.state.principal = _system_principal()
            return await call_next(request)
        policy = required_caps(request.method, request.url.path)
        if policy is None:
            return await call_next(request)
        try:
            principal = resolve_principal(store, request)
        except Exception:  # noqa: BLE001
            logging.getLogger("supplydrift").exception("principal resolution failed")
            return JSONResponse(status_code=500, content={"error": "internal server error"})
        if principal is None:
            return JSONResponse(status_code=401, content={"error": "authentication required"})
        if principal.is_user and request.method in MUTATING:
            sent = request.headers.get(CSRF_HEADER, "")
            if not principal.csrf or not secrets.compare_digest(sent, principal.csrf):
                return JSONResponse(status_code=403, content={"error": "CSRF token missing or invalid"})
        if policy != "authed" and not (principal.caps & policy):
            return JSONResponse(status_code=403, content={"error": "insufficient permissions"})
        request.state.principal = principal
        return await call_next(request)

    # -- public --
    @api.get("/api/health")
    def health():
        return {"status": "ok", "auth": auth_enabled()}

    # -- session auth --
    @api.post("/api/auth/login")
    async def login(request: Request):
        body = await _json(request)
        username = str(body.get("username", "")).strip().lower()
        password = str(body.get("password", ""))
        # Throttle per username AND per source IP (both DB-backed, consistent across
        # workers). The per-username cap blocks targeted brute force; the (generous)
        # per-IP cap slows password-spraying one password across many usernames from a
        # single host. See Store.LOGIN_IP_MAX_FAILS for the shared-proxy caveat.
        client_ip = request.client.host if request.client else ""
        ip_key = f"ip:{client_ip}" if client_ip else ""
        if store.login_throttled(username) or (
            ip_key and store.login_throttled(ip_key, max_fails=store.LOGIN_IP_MAX_FAILS)
        ):
            return JSONResponse(status_code=429, content={"error": "too many attempts; try again later"})
        user = store.verify_login(username, password)
        if user is None:
            store.record_login_failure(username)
            if ip_key:
                store.record_login_failure(ip_key)
            return JSONResponse(status_code=401, content={"error": "invalid username or password"})
        # Clear the username counter on success; leave the IP counter so a spraying
        # host that lands one valid credential doesn't reset its whole IP budget.
        store.clear_login_attempts(username)
        sess = store.create_session(user["id"])
        resp = JSONResponse(content={"user": user, "csrf_token": sess["csrf_token"]})
        resp.set_cookie(SESSION_COOKIE, sess["session_id"], httponly=True, secure=_secure_cookies(),
                        samesite="lax", max_age=store.SESSION_TTL_HOURS * 3600, path="/")
        return resp

    @api.post("/api/auth/logout")
    def logout(request: Request):
        sid = request.cookies.get(SESSION_COOKIE)
        if sid:
            store.delete_session(sid)
        resp = JSONResponse(content={"status": "logged_out"})
        resp.delete_cookie(SESSION_COOKIE, path="/", httponly=True,
                           secure=_secure_cookies(), samesite="lax")
        return resp

    @api.get("/api/auth/me")
    def me(request: Request):
        p: Principal = request.state.principal
        if p.kind == "token":
            return {"kind": "token", "scope": p.scope}
        return {"kind": p.kind, "username": p.username, "role": p.role, "csrf_token": p.csrf}

    @api.post("/api/auth/change-password")
    async def change_password(request: Request):
        p: Principal = request.state.principal
        if not p.is_user or not p.id:
            return JSONResponse(status_code=403, content={"error": "not a user session"})
        body = await _json(request)
        if store.verify_login(p.username, str(body.get("old_password", ""))) is None:
            return JSONResponse(status_code=403, content={"error": "current password is incorrect"})
        new_pw = str(body.get("new_password", ""))
        if len(new_pw) < store.PASSWORD_MIN_LENGTH:
            return JSONResponse(status_code=400, content={
                "error": f"new password must be at least {store.PASSWORD_MIN_LENGTH} characters"})
        store.update_user(p.id, password=new_pw)  # revokes ALL of this user's sessions
        # Rotate: issue a fresh session so the current caller stays logged in while any
        # other (possibly stolen) sessions are now invalid.
        sess = store.create_session(p.id)
        resp = JSONResponse(content={"status": "password_changed", "csrf_token": sess["csrf_token"]})
        resp.set_cookie(SESSION_COOKIE, sess["session_id"], httponly=True, secure=_secure_cookies(),
                        samesite="lax", max_age=store.SESSION_TTL_HOURS * 3600, path="/")
        return resp

    # -- admin: users (admin only via policy) --
    @api.get("/api/admin/users")
    def list_users():
        return store.list_users()

    @api.post("/api/admin/users")
    async def create_user(request: Request):
        body = await _json(request)
        try:
            return JSONResponse(status_code=201, content=store.create_user(
                body.get("username", ""), body.get("password", ""), body.get("role", "member")))
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

    @api.put("/api/admin/users/{user_id}")
    async def update_user(user_id: str, request: Request):
        body = await _json(request)
        try:
            out = store.update_user(user_id, role=body.get("role"), disabled=body.get("disabled"),
                                    password=body.get("password"))
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})
        return out or JSONResponse(status_code=404, content={"error": "user not found"})

    @api.delete("/api/admin/users/{user_id}")
    def delete_user(user_id: str, request: Request):
        if request.state.principal.id == user_id:
            return JSONResponse(status_code=400, content={"error": "cannot delete your own account"})
        ok = store.delete_user(user_id)
        return JSONResponse(status_code=200 if ok else 404, content={"deleted": ok})

    # -- tokens: member+ self-service (scoped); admins see/revoke all --
    @api.get("/api/admin/tokens")
    def list_tokens(request: Request):
        p: Principal = request.state.principal
        toks = store.list_tokens()
        if ADMIN not in p.caps:
            toks = [t for t in toks if t.get("created_by") == p.username]
        return toks

    @api.post("/api/admin/tokens")
    async def create_token(request: Request):
        p: Principal = request.state.principal
        body = await _json(request)
        scope = body.get("scope", "")
        if scope not in auth.TOKEN_SCOPES:
            return JSONResponse(status_code=400, content={"error": f"scope must be one of {auth.TOKEN_SCOPES}"})
        if scope == "runner" and ADMIN not in p.caps:
            return JSONResponse(status_code=403, content={"error": "runner tokens require admin"})
        return JSONResponse(status_code=201, content=store.create_token(
            body.get("name", scope), scope, created_by=p.username or "admin"))

    @api.delete("/api/admin/tokens/{token_id}")
    def revoke_token(token_id: str, request: Request):
        p: Principal = request.state.principal
        if ADMIN not in p.caps:
            owned = any(t["id"] == token_id and t.get("created_by") == p.username for t in store.list_tokens())
            if not owned:
                return JSONResponse(status_code=403, content={"error": "not your token"})
        ok = store.revoke_token(token_id)
        return JSONResponse(status_code=200 if ok else 404, content={"revoked": ok})
