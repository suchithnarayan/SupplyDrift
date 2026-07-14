"""CLI for the GitHub repository sync (mirror of the image-scanner CLI)."""
from __future__ import annotations

import argparse
import json
import logging
import sys

from supplydrift_sandbox import SandboxError

from .config import load_config, load_config_from_url
from .pipeline import run
from .sbom import tool_sandbox


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if sandbox := getattr(record, "sandbox", None):
            payload["sandbox"] = sandbox
        return json.dumps(payload)


def _setup_logging(verbose: bool, quiet: bool, fmt: str) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(_JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", datefmt="%H:%M:%S"))
    logger = logging.getLogger("gbom_sync")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gbom_sync.py",
        description="Scan GitHub repositories for phantom dependencies and sync them to the SupplyDrift platform.",
    )
    parser.add_argument(
        "targets", nargs="*", metavar="REPO",
        help="Repo path or github URL/owner-repo to scan locally (no platform or config needed)",
    )
    parser.add_argument("--config", help="Path to the YAML config")
    parser.add_argument("--config-url", metavar="URL", help="Fetch config from the platform (e.g. http://host:8765/api/scanner/config)")
    parser.add_argument("--source", action="append", default=[], metavar="NAME", help="Only run the named source(s)")
    parser.add_argument("--dry-run", action="store_true", help="List repositories only; do not clone/scan")
    parser.add_argument("--no-push", action="store_true", help="Scan but do not POST to the platform")
    parser.add_argument("--format", choices=["summary", "json"], default="summary", help="Result output style")
    parser.add_argument("-o", "--output", help="Write the output to a file")
    parser.add_argument(
        "--report", action="store_true",
        help="Local mode: flattened {target, components, vulnerabilities, issues} JSON",
    )
    parser.add_argument(
        "--malware", action="store_true",
        help="Local mode: also check scanned packages against OSV's malicious-package (MAL-*) feed",
    )
    parser.add_argument("--serve", action="store_true",
                        help="Runner mode: poll the platform for queued github scan jobs and run them")
    parser.add_argument("--poll-interval", type=int, default=15, metavar="SECONDS",
                        help="Runner mode: seconds between polls when the queue is empty (default 15)")
    parser.add_argument("--once", action="store_true",
                        help="Runner mode: process at most one job, then exit (for cron / tests)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (DEBUG) logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet: warnings and errors only")
    parser.add_argument("--log-format", choices=["text", "json"], default="text", help="Progress log format")
    return parser


def _post_json(url: str, body: dict, timeout: int = 600):
    """POST JSON, return the parsed response (None on null body)."""
    import urllib.request

    from .config import auth_headers
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", **auth_headers()}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else None


def _scoped_config_url(config_url: str, connector_id: str | None) -> str:
    """Scope the scanner-config fetch to the claimed connector so the runner only
    receives that one connector's secret (least-privilege)."""
    if not connector_id:
        return config_url
    from urllib.parse import quote
    sep = "&" if "?" in config_url else "?"
    return f"{config_url}{sep}connector_id={quote(str(connector_id), safe='')}"


def _claim_and_run(base: str, config_url: str, runner_id: str, *, post, run_pipeline, log) -> bool:
    """Claim one queued github job, run it for that source, report status. False if queue empty."""
    job = post(f"{base}/api/scan/runs/claim", {"job_type": "github", "runner_id": runner_id})
    if not job:
        return False
    log.info("claimed run %s for source '%s'", job["id"], job["source_name"])
    try:
        config = load_config_from_url(_scoped_config_url(config_url, job.get("connector_id")))
        # Push back to the SAME platform we claimed from (the config's public URL may be
        # an external/browser address that isn't reachable from inside the runner).
        config.platform.url = base
        action = (job.get("summary") or {}).get("action") or "scan"
        inventory_only = action == "refresh"
        result = run_pipeline(
            config,
            sources_filter={job["source_name"]},
            push=True,
            inventory_only=inventory_only,
        )
        s = result.summary()
        s["action"] = action
        status = (
            "failed"
            if result.errors
            or (not inventory_only and s["discovered"] and s["scanned_ok"] == 0)
            else "succeeded"
        )
        post(f"{base}/api/scan/runs/{job['id']}/complete",
             {"status": status, "summary": s, "error": "; ".join(result.errors[:5]),
              "runner_id": runner_id})
        log.info("run %s %s — %s", job["id"], status, s)
    except Exception as exc:  # noqa: BLE001 — a failed job must be reported, not crash the runner
        log.error("run %s failed: %s", job["id"], exc)
        post(f"{base}/api/scan/runs/{job['id']}/complete",
             {"status": "failed", "summary": {}, "error": str(exc), "runner_id": runner_id})
    return True


def _serve(args: argparse.Namespace, log: logging.Logger) -> int:
    import os
    import socket
    import time
    from urllib.parse import urlparse

    if not args.config_url:
        print("error: --serve requires --config-url (the platform)", file=sys.stderr)
        return 2
    try:
        tool_sandbox.ensure_ready()
    except SandboxError as exc:
        log.critical("github runner sandbox preflight failed: %s", exc)
        return 2
    parsed = urlparse(args.config_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    runner_id = f"{socket.gethostname()}-{os.getpid()}"
    log.info("github runner: polling %s for jobs as %s (every %ds)", base, runner_id, args.poll_interval)
    while True:
        try:
            worked = _claim_and_run(base, args.config_url, runner_id, post=_post_json, run_pipeline=run, log=log)
        except Exception as exc:  # noqa: BLE001 — keep the runner alive across platform blips
            log.warning("poll error: %s", exc)
            worked = False
        if args.once:
            return 0
        if not worked:
            time.sleep(args.poll_interval)


def _render(result, fmt: str) -> str:
    s = result.summary()
    if fmt == "json":
        return json.dumps([r.payload for r in result.results if r.ok], indent=2)
    lines = [
        "=" * 60,
        "  GitHub Shadow-Deps - SupplyDrift Vector 1",
        "=" * 60,
        f"Discovered repos  : {s['discovered']}",
        f"By source         : {json.dumps(s['by_source'])}",
        f"Scanned OK        : {s['scanned_ok']}",
        f"Scan failures     : {s['scanned_failed']}",
        f"Components total  : {s['total_components']}",
        f"Findings total    : {s['total_findings']}",
        f"Pushed to platform: {s['pushed']}",
    ]
    if s["errors"]:
        lines.append("-" * 60)
        lines.append("Errors:")
        lines.extend(f"  - {e}" for e in s["errors"])
    lines.append("=" * 60)
    return "\n".join(lines)


def _run_local(args: argparse.Namespace, log: logging.Logger) -> int:
    """Local CLI mode: scan repo path(s)/URL(s) directly to a JSON file (no platform)."""
    from pathlib import Path

    from .config import ScannerConfig
    from .pipeline import flatten_payload, run_local

    if args.config:
        try:
            scanner_cfg = load_config(args.config).scanner
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        scanner_cfg = ScannerConfig()

    log.info("local scan of %d repo(s) (sbom=%s, vulnerabilities=%s)",
             len(args.targets), scanner_cfg.scan_sbom, scanner_cfg.scan_vulnerabilities)
    result = run_local(args.targets, scanner_cfg)
    payloads = [r.payload for r in result.results if r.ok]
    if args.malware:
        from .osv_query import enrich_payload_with_malware
        added = sum(enrich_payload_with_malware(p) for p in payloads)
        log.info("malware check (OSV): %d malicious finding(s)", added)
    data = [flatten_payload(p) for p in payloads] if args.report else payloads
    rendered = json.dumps(data, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {'report' if args.report else 'payload'} JSON for {len(payloads)} repo(s) "
              f"to {args.output}", file=sys.stderr)
    else:
        print(rendered)
    return 1 if result.errors else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose, args.quiet, args.log_format)
    log = logging.getLogger("gbom_sync.cli")

    # Runner mode: poll the platform queue and execute github jobs.
    if args.serve:
        return _serve(args, log)

    # Local CLI mode: bare repo path/URL -> JSON file, no platform/config.
    if args.targets:
        return _run_local(args, log)

    if not args.config and not args.config_url:
        print("error: pass a repo path/URL to scan locally, or --config/--config-url "
              "for a configured run", file=sys.stderr)
        return 2

    source = args.config_url or args.config
    log.info("gbom_sync starting (config: %s)", source)
    try:
        config = load_config_from_url(args.config_url) if args.config_url else load_config(args.config)
    except (RuntimeError, ValueError, OSError) as exc:
        log.error("could not load config from %s: %s", source, exc)
        print(f"error: {exc}", file=sys.stderr)
        return 2
    log.info("loaded %d github source(s)", len(config.sources))

    sources_filter = set(args.source) if args.source else None
    push = False if args.no_push else None
    result = run(config, sources_filter=sources_filter, dry_run=args.dry_run, push=push)

    rendered = _render(result, args.format)
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {args.format} output to {args.output}", file=sys.stderr)
    else:
        print(rendered)
    if result.errors and not args.dry_run:
        return 1
    return 0
