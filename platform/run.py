#!/usr/bin/env python3
"""Run the SupplyDrift platform on FastAPI + uvicorn.

The platform entry point. ``app.py`` holds the ``Store`` + helpers; ``server.py``
is the FastAPI HTTP layer; this launches it with uvicorn.

    python3 run.py --host 0.0.0.0 --port 8765 --db data/supplydrift.db
    python3 run.py --reload          # dev auto-reload
"""
import argparse
import os

from pathlib import Path


def _auth_disabled() -> bool:
    return os.environ.get("SUPPLYDRIFT_AUTH", "enabled").strip().lower() == "disabled"


def _is_loopback(host: str) -> bool:
    h = (host or "").strip().lower()
    return h in ("", "localhost", "::1") or h == "127.0.0.1" or h.startswith("127.")


def main() -> None:
    parser = argparse.ArgumentParser(description="SupplyDrift platform (FastAPI/uvicorn)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", type=Path, default=Path(os.environ.get("SUPPLYDRIFT_DB", "data/supplydrift.db")))
    parser.add_argument("--load-demo", action="store_true", help="Load demo data before serving")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes (dev)")
    args = parser.parse_args()

    # Safety rail: never expose an UNAUTHENTICATED admin API on a public interface.
    if (_auth_disabled() and not _is_loopback(args.host)
            and os.environ.get("SUPPLYDRIFT_I_UNDERSTAND_AUTH_DISABLED") != "1"):
        parser.error(
            f"refusing to start: SUPPLYDRIFT_AUTH=disabled with --host {args.host} would expose an "
            "UNAUTHENTICATED admin API on a non-loopback interface. Bind 127.0.0.1, enable auth, or set "
            "SUPPLYDRIFT_I_UNDERSTAND_AUTH_DISABLED=1 to override.")

    # server.py builds its Store from these at import time.
    os.environ["SUPPLYDRIFT_DB"] = str(args.db)
    if args.load_demo:
        os.environ["SUPPLYDRIFT_LOAD_DEMO"] = "1"

    import uvicorn

    database_url = os.environ.get("SUPPLYDRIFT_DATABASE_URL", "")
    database_target = (
        f"{database_url.split(':', 1)[0]} via SUPPLYDRIFT_DATABASE_URL"
        if database_url
        else f"sqlite:///{args.db}"
    )
    print(f"SupplyDrift platform (FastAPI) at http://{args.host}:{args.port}  ·  DB: {database_target}")
    uvicorn.run("server:api", host=args.host, port=args.port, reload=args.reload, log_level="info")


if __name__ == "__main__":
    main()
