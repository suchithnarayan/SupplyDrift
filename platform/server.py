"""FastAPI HTTP layer for the SupplyDrift platform.

Behavior-preserving migration of the stdlib ``ApiHandler``: every ``/api/*`` route
maps 1:1 to the SAME ``Store`` methods (imported verbatim from ``app.py``) and
returns the SAME JSON shapes. Only the transport changes — run with uvicorn
instead of ``http.server``. The Store, SQLite schema, and all business logic are
untouched, so the Phase-0 golden contract tests pass identically here.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import zlib
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response

import app as core  # the Store + helpers + SCHEMA + demo_payload (no server side effects)
import authz

# Ingest DoS guards (configurable). Real scanner payloads are a few MB even gzipped;
# these caps are generous but bound memory use against oversized / gzip-bomb bodies.
_MAX_BODY = int(os.environ.get("SUPPLYDRIFT_MAX_BODY_MB", "64")) * 1024 * 1024
_MAX_DECOMPRESSED = int(os.environ.get("SUPPLYDRIFT_MAX_DECOMPRESSED_MB", "256")) * 1024 * 1024


def _qp(request: Request) -> dict[str, list[str]]:
    """Query string -> {key: [values]} — exactly what the Store methods expect."""
    return parse_qs(request.url.query)


def _gunzip_bounded(raw: bytes, limit: int) -> bytes:
    """Decompress gzip with a hard output ceiling so a small body can't expand
    without bound (gzip bomb)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(raw, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise HTTPException(status_code=413, detail="decompressed body too large")
    out += d.flush()
    if len(out) > limit:
        raise HTTPException(status_code=413, detail="decompressed body too large")
    return out


async def _body(request: Request) -> dict:
    # Reject oversized bodies up front via Content-Length when present.
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > _MAX_BODY:
        raise HTTPException(status_code=413, detail="request body too large")
    raw = await request.body()
    if len(raw) > _MAX_BODY:
        raise HTTPException(status_code=413, detail="request body too large")
    if raw and (request.headers.get("content-encoding") or "").lower() == "gzip":
        raw = _gunzip_bounded(raw, _MAX_DECOMPRESSED)
    return json.loads(raw or b"{}")


def create_app(store: "core.Store") -> FastAPI:
    # Interactive API docs + OpenAPI schema expose the full route map; serve them only
    # in dev (SUPPLYDRIFT_INSECURE=1) so production doesn't hand the schema to every
    # authenticated (incl. viewer) caller. Redoc stays off.
    _dev = os.environ.get("SUPPLYDRIFT_INSECURE", "").strip() == "1"
    api = FastAPI(
        title="SupplyDrift",
        docs_url="/api/docs" if _dev else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if _dev else None,
    )

    @api.exception_handler(Exception)
    async def _on_error(_request: Request, exc: Exception):  # noqa: ANN202
        # Log the detail server-side; never return raw exception text (it can carry
        # SQL fragments, file paths, or secret-key validation messages) to clients.
        logging.getLogger("supplydrift").exception("unhandled error: %s", exc)
        return JSONResponse(status_code=500, content={"error": "internal server error"})

    # ---- GET ----------------------------------------------------------------
    @api.get("/api/summary")
    def summary():
        return store.summary()

    @api.get("/api/assets")
    def list_assets(request: Request):
        return store.list_assets(_qp(request))

    @api.get("/api/assets/{asset_id}/components")
    def asset_components(asset_id: str, request: Request):
        return store.asset_components(asset_id, _qp(request))

    @api.get("/api/assets/{asset_id}/findings")
    def asset_findings(asset_id: str, request: Request):
        return store.asset_findings(asset_id, _qp(request))

    @api.get("/api/assets/{asset_id}")
    def get_asset(asset_id: str):
        asset = store.get_asset(asset_id)
        if asset is None:
            return JSONResponse(status_code=404, content={"error": "asset not found"})
        return asset

    @api.get("/api/components")
    def list_components(request: Request):
        return store.list_components(_qp(request))

    @api.get("/api/sbom/packages")
    def sbom_packages(request: Request):
        return store.sbom_packages(_qp(request))

    @api.get("/api/sbom/versions")
    def sbom_versions(request: Request):
        return store.sbom_versions(_qp(request))

    @api.get("/api/sbom/assets")
    def sbom_assets(request: Request):
        return store.sbom_assets(_qp(request))

    @api.get("/api/vulnerabilities")
    def list_vulnerabilities(request: Request):
        return store.list_vulnerabilities(_qp(request))

    @api.get("/api/findings")
    def list_findings(request: Request):
        return store.list_findings(_qp(request))

    @api.get("/api/connectors")
    def list_connectors():
        return store.list_connectors()

    @api.get("/api/connectors/{connector_id}")
    def get_connector(connector_id: str):
        connector = store.get_connector(connector_id)
        if connector is None:
            return JSONResponse(status_code=404, content={"error": "connector not found"})
        return connector

    @api.get("/api/scanner/config")
    def scanner_config(request: Request):
        # Real decrypted secrets only for bearer-authenticated runner tokens.
        # Human operators, including admins with QUEUE capability, get masked
        # values so the browser never receives stored connector credentials.
        principal = getattr(request.state, "principal", None)
        include_secrets = bool(
            principal and principal.kind == "token" and principal.scope == "runner"
        )
        # A runner scopes the request to the connector it just claimed so it only
        # receives that connector's secret (least-privilege; see Store.scanner_config).
        only = (_qp(request).get("connector_id") or [None])[0] or None
        return store.scanner_config(include_secrets=include_secrets, only_connector_id=only)

    @api.get("/api/graph")
    def graph(request: Request):
        return store.graph(_qp(request))

    @api.get("/api/blast-radius")
    def blast_radius(request: Request):
        return store.blast_radius(_qp(request))

    @api.get("/api/alerts")
    def list_alerts(request: Request):
        return store.list_alerts(_qp(request))

    @api.get("/api/settings/malware")
    def get_malware_settings():
        return store.get_malware_settings()

    @api.get("/api/malware/cursor")
    def malware_cursor():
        return store.malware_cursor()

    @api.get("/api/scan/runs")
    def list_scan_runs(request: Request):
        return store.list_scan_runs(_qp(request))

    @api.get("/api/connectors/{connector_id}/scan/latest")
    def latest_scan_run(connector_id: str):
        return store.latest_scan_run(connector_id)

    # ---- POST ---------------------------------------------------------------
    @api.post("/api/sync/{source_type}")
    async def sync_source(source_type: str, request: Request):
        result = store.sync_source_payload(source_type, await _body(request))
        return JSONResponse(status_code=201, content=result)

    @api.post("/api/ingest")
    async def ingest(request: Request):
        payload = await _body(request)
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="request body must be a JSON object")
        assets = payload.get("assets")
        if not isinstance(assets, list) or not assets:
            raise HTTPException(status_code=422, detail="assets must be a non-empty array")
        return JSONResponse(status_code=201, content=store.ingest(payload))

    @api.post("/api/connectors")
    async def create_connector(request: Request):
        return JSONResponse(status_code=201, content=store.save_connector(await _body(request)))

    def _demo_enabled() -> bool:
        # Demo routes are destructive (reset wipes all data); keep them off unless
        # explicitly enabled, so they aren't exposed in production deployments.
        return os.environ.get("SUPPLYDRIFT_DEMO", "").lower() in ("1", "true", "yes", "on")

    @api.post("/api/demo/reset")
    def demo_reset():
        if not _demo_enabled():
            return JSONResponse(status_code=404, content={"error": "not found"})
        store.reset()
        return {"status": "reset", **store.ingest(core.demo_payload())}

    @api.post("/api/demo/load")
    def demo_load():
        if not _demo_enabled():
            return JSONResponse(status_code=404, content={"error": "not found"})
        return {"status": "loaded", **store.ingest(core.demo_payload())}

    @api.post("/api/malware/scan")
    def malware_scan():
        # "Run analysis now": enqueue a malware job; the malware runner claims + executes it.
        return JSONResponse(status_code=202, content=store.enqueue_malware_scan())

    @api.post("/api/malware/match")
    async def malware_match(request: Request):
        # The malware runner fetches the OSV MAL-* delta and POSTs the specs here;
        # the platform does the in-DB match + alert/Slack (matching stays close to the data).
        import osv_malware as osv
        body = await _body(request)
        if not store.get_malware_settings()["malware_enabled"]:
            return {"skipped": "malware analysis disabled", "matched": 0, "new": 0, "active_total": 0}
        specs = [osv.spec_from_dict(d) for d in (body.get("specs") or [])]
        return store.match_malware_specs(specs, scanned_at=body.get("scanned_at"))

    # ---- scan job queue (UI Scan button -> runners) ----
    @api.post("/api/connectors/{connector_id}/scan")
    def enqueue_scan(connector_id: str):
        try:
            return JSONResponse(status_code=202, content=store.enqueue_scan(connector_id))
        except ValueError as exc:
            return JSONResponse(status_code=404, content={"error": str(exc)})

    @api.post("/api/connectors/{connector_id}/refresh")
    def enqueue_refresh(connector_id: str):
        try:
            return JSONResponse(status_code=202, content=store.enqueue_refresh(connector_id))
        except ValueError as exc:
            return JSONResponse(status_code=404, content={"error": str(exc)})

    @api.post("/api/scan/runs/claim")
    async def claim_scan_run(request: Request):
        body = await _body(request)
        return store.claim_scan_run(body.get("job_type", ""), body.get("runner_id", "unknown"))

    @api.post("/api/scan/runs/{run_id}/complete")
    async def complete_scan_run(run_id: str, request: Request):
        body = await _body(request)
        return store.complete_scan_run(run_id, body.get("status", "failed"),
                                       body.get("summary"), body.get("error", ""),
                                       runner_id=body.get("runner_id"))

    # ---- stop a scan (UI 'Stop' button): cancel a queued/running run --------
    @api.post("/api/scan/runs/{run_id}/cancel")
    def cancel_scan_run(run_id: str):
        return store.cancel_scan_run(run_id)

    @api.post("/api/connectors/{connector_id}/scan/cancel")
    def cancel_connector_scan(connector_id: str):
        return store.cancel_connector_scan(connector_id)

    # ---- PUT / DELETE -------------------------------------------------------
    @api.put("/api/settings/malware")
    async def update_malware_settings(request: Request):
        return store.update_malware_settings(await _body(request))

    @api.put("/api/connectors/{connector_id}")
    async def update_connector(connector_id: str, request: Request):
        return store.save_connector(await _body(request), connector_id=connector_id)

    @api.delete("/api/connectors/{connector_id}")
    def delete_connector(connector_id: str):
        deleted = store.delete_connector(connector_id)
        return JSONResponse(status_code=200 if deleted else 404, content={"deleted": deleted})

    # ---- auth: enforcement middleware + login/logout/me + admin routes --------
    # (registered BEFORE the catch-alls so /api/auth/* + /api/admin/* aren't shadowed)
    authz.install_auth(api, store)

    # ---- /api catch-all (unknown endpoint -> 404, like the stdlib server) ---
    @api.api_route("/api/{_rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def api_not_found(_rest: str):
        return JSONResponse(status_code=404, content={"error": "not found"})

    # ---- static SPA (history fallback) --------------------------------------
    static_root: Path = core.STATIC_ROOT

    @api.get("/{full_path:path}")
    def spa(full_path: str):
        if full_path:
            target = (static_root / full_path).resolve()
            if target.is_file() and static_root.resolve() in target.parents:
                return FileResponse(target)
        index = static_root / "index.html"
        if index.is_file():
            return FileResponse(index)
        return Response("SupplyDrift API", media_type="text/plain")

    # CORS added LAST so it is the outermost middleware (adds headers even to 401s).
    # With allow_credentials=True we must not use "*" for methods/headers — enumerate
    # exactly what the SPA sends.
    api.add_middleware(
        CORSMiddleware, allow_origins=authz.cors_origins(), allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token", "Content-Encoding", "Authorization"],
    )
    return api


def _start_malware_enqueue_scheduler(the_store: "core.Store") -> None:
    """Lightweight interval timer: when malware analysis is enabled, ENQUEUE a malware
    job every `malware_interval_minutes` (a cheap insert — the malware runner does the
    actual OSV work). Replaces the old in-process analysis scheduler + monitor container.
    Disable with MALWARE_SCHEDULER=off.
    """
    import time

    def loop() -> None:
        while True:
            try:
                interval = the_store.get_malware_settings()["malware_interval_minutes"]
            except Exception:
                interval = 60
            time.sleep(max(60, interval * 60))
            try:
                if the_store.get_malware_settings()["malware_enabled"]:
                    the_store.enqueue_malware_scan()
            except Exception:
                pass

    threading.Thread(target=loop, name="malware-enqueue-scheduler", daemon=True).start()


# Module-level app for `uvicorn server:api` — configured from the environment.
store = core.Store(Path(os.environ.get("SUPPLYDRIFT_DB", core.DEFAULT_DB)))
if os.environ.get("SUPPLYDRIFT_LOAD_DEMO"):
    store.ingest(core.demo_payload())
api = create_app(store)
authz.bootstrap(store)  # seed env-var admin + register the bundled runner token
# A restart means any 'running' run from before is orphaned: the runner that claimed
# it is gone (or, after `compose down/up`, a fresh runner that only claims 'queued'
# jobs), so it will never POST /complete and the source would stick "Scanning…".
# Reap ALL running on boot regardless of age (timeout 0). This is safe: if a runner
# was merely slow and later completes, its /complete overwrites the reaped row.
store.reap_stale_scan_runs(timeout_seconds=0)
if os.environ.get("MALWARE_SCHEDULER") != "off":
    _start_malware_enqueue_scheduler(store)
