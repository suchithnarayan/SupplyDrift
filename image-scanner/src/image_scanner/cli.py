"""Command-line interface for the image scanner."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from . import __version__
from ._sandbox import tool_sandbox
from .config import load_config, load_config_from_url
from .pipeline import run
from supplydrift_sandbox import SandboxError


class _JsonLogFormatter(logging.Formatter):
    """One JSON object per log line — friendly for cron log aggregation."""

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
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", datefmt="%H:%M:%S")
        )
    logger = logging.getLogger("image_scanner")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="image_scan.py",
        description=(
            "Container image SBOM extraction with a pluggable connector framework "
            "(SupplyDrift Vector 2). One core scanner; per-source connectors discover "
            "which images to scan."
        ),
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="IMAGE",
        help="Image reference(s) to scan locally (e.g. nginx:latest) — no platform or config needed",
    )
    parser.add_argument("--config", type=Path, help="Path to the YAML config")
    parser.add_argument(
        "--config-url",
        metavar="URL",
        help="Fetch config from the platform instead of a file (e.g. http://host:8765/api/scanner/config)",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="NAME",
        help="Only run the named source(s) (repeatable)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Discover and list target images only; do not pull or scan",
    )
    parser.add_argument("--no-push", action="store_true", help="Scan but do not POST to the platform")
    parser.add_argument(
        "--inventory-only",
        action="store_true",
        help="Refresh discovered image/topology inventory without running Syft or Grype",
    )
    parser.add_argument(
        "--format",
        choices=["summary", "json", "targets"],
        default="summary",
        help="summary (default), json (full payloads), or targets (discovered refs)",
    )
    parser.add_argument("-o", "--output", type=Path, help="Write the chosen output to a file")
    parser.add_argument(
        "--report",
        action="store_true",
        help="Local mode: flattened {target, components, vulnerabilities} JSON instead of the platform payload",
    )
    parser.add_argument(
        "--malware",
        action="store_true",
        help="Local mode: also check scanned packages against OSV's malicious-package (MAL-*) feed",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (DEBUG) logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet: warnings and errors only")
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Progress log format on stderr (json for log aggregation)",
    )
    parser.add_argument("--serve", action="store_true",
                        help="Runner mode: poll the platform for queued image scan jobs and run them")
    parser.add_argument("--poll-interval", type=int, default=15, metavar="SECONDS",
                        help="Runner mode: seconds between polls when the queue is empty (default 15)")
    parser.add_argument("--once", action="store_true",
                        help="Runner mode: process at most one job, then exit (for cron / tests)")
    parser.add_argument("--version", action="version", version=f"image-scanner {__version__}")
    return parser


def _post_json(url: str, body: dict, timeout: int = 600) -> Any:
    """POST JSON, return the parsed response (None on error / null body)."""
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
    """Claim one queued image job, run it for that source, report status. False if queue empty."""
    job = post(f"{base}/api/scan/runs/claim", {"job_type": "image", "runner_id": runner_id})
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
        log.critical("image runner sandbox preflight failed: %s", exc)
        return 2
    parsed = urlparse(args.config_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    runner_id = f"{socket.gethostname()}-{os.getpid()}"
    log.info("image runner: polling %s for jobs as %s (every %ds)", base, runner_id, args.poll_interval)
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
    if fmt == "targets":
        lines = [
            f"{t.source:18} {t.reference}" + (f"  (pushed {t.pushed_at})" if t.pushed_at else "")
            for t in result.discovered
        ]
        if result.errors:
            lines.extend(["", "Errors:"] if lines else ["Errors:"])
            lines.extend(f"  - {e}" for e in result.errors)
        return "\n".join(lines) or "(no images discovered)"
    if fmt == "json":
        return json.dumps(result.payloads, indent=2)
    # summary
    s = result.summary()
    lines = [
        "=" * 60,
        "  Image Scanner - SupplyDrift Vector 2",
        "=" * 60,
        f"Discovered images : {s['discovered']}",
        f"By source         : {json.dumps(s['by_source'])}",
        f"Scanned OK        : {s['scanned_ok']}",
        f"Scan failures     : {s['scanned_failed']}",
        f"Components total  : {s['total_components']}",
        f"Vulnerabilities   : {s['total_vulnerabilities']}",
        f"Pushed to platform: {s['pushed']}",
    ]
    if s["errors"]:
        lines.append("-" * 60)
        lines.append("Errors:")
        lines.extend(f"  - {e}" for e in s["errors"])
    lines.append("=" * 60)
    return "\n".join(lines)


def _run_local(args: argparse.Namespace, log: logging.Logger) -> int:
    """Local CLI mode: scan image references directly to a JSON file (no platform)."""
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

    log.info("local scan of %d image(s) (extractor=%s, vulnerabilities=%s)",
             len(args.targets), scanner_cfg.extractor, scanner_cfg.scan_vulnerabilities)
    result = run_local(args.targets, scanner_cfg)
    if args.malware:
        from .core.osv_query import enrich_payload_with_malware
        added = sum(enrich_payload_with_malware(p) for p in result.payloads)
        log.info("malware check (OSV): %d malicious finding(s)", added)
    data = [flatten_payload(p) for p in result.payloads] if args.report else result.payloads
    rendered = json.dumps(data, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {'report' if args.report else 'payload'} JSON for {len(result.payloads)} image(s) "
              f"to {args.output}", file=sys.stderr)
    else:
        print(rendered)
    return 1 if result.errors else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose, args.quiet, args.log_format)
    log = logging.getLogger("image_scanner.cli")

    # Runner mode: poll the platform queue and execute jobs.
    if args.serve:
        return _serve(args, log)

    # Local CLI mode: bare image references -> JSON file, no platform/config.
    if args.targets:
        return _run_local(args, log)

    if not args.config and not args.config_url:
        print("error: pass image reference(s) to scan locally, or --config/--config-url "
              "for a configured run", file=sys.stderr)
        return 2

    source = args.config_url or str(args.config)
    log.info("image-scanner %s starting (config: %s)", __version__, source)
    try:
        config = (
            load_config_from_url(args.config_url) if args.config_url else load_config(args.config)
        )
    except (RuntimeError, ValueError, OSError) as exc:
        log.error("could not load config from %s: %s", source, exc)
        print(f"error: {exc}", file=sys.stderr)
        return 2

    log.info(
        "loaded %d registr%s and %d service(s); extractor=%s",
        len(config.registries),
        "y" if len(config.registries) == 1 else "ies",
        len(config.services),
        config.scanner.extractor,
    )

    sources_filter = set(args.source) if args.source else None
    push = False if args.no_push else None

    result = run(
        config,
        sources_filter=sources_filter,
        dry_run=args.dry_run,
        push=push,
        inventory_only=args.inventory_only,
    )

    rendered = _render(result, args.format)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {args.format} output to {args.output}", file=sys.stderr)
    else:
        print(rendered)

    # Surface discovery/scan errors as a soft failure exit code.
    if result.errors and not args.dry_run:
        return 1
    return 0
