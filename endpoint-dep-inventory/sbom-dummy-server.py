#!/usr/bin/env python3
"""Small local HTTP receiver for testing collect-sbom-inventory.sh uploads.

NOT FOR PRODUCTION. This is a test-only receiver: it does not require a token by
default, performs no real authentication, and writes every POST body to disk. Do
not expose it beyond localhost. As guardrails it refuses to bind a non-loopback
host unless --i-know-this-is-insecure is passed, and it caps both the compressed
and decompressed request sizes so a small gzip body cannot exhaust memory.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

# Default caps so an accidental deploy cannot be trivially memory-exhausted.
# The collector's own batches are bounded by SBOM_MAX_BATCH_BYTES (2 MiB default).
DEFAULT_MAX_BYTES = 64 * 1024 * 1024  # 64 MiB compressed request body.
DEFAULT_MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024  # 256 MiB after gunzip.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", ""})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Receive SBOM inventory batches and save each POST body as JSON."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address. Must be loopback (127.0.0.1/::1/localhost) unless "
        "--i-know-this-is-insecure is given. Default: 127.0.0.1",
    )
    parser.add_argument(
        "--i-know-this-is-insecure",
        dest="allow_insecure_bind",
        action="store_true",
        help="Permit binding a non-loopback --host. This test server has no real "
        "auth and writes every body to disk; only use on a trusted, isolated network.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Bind port. Use 0 for a random free port. Default: 8080",
    )
    parser.add_argument(
        "--out-dir",
        default="./received-sbom-batches",
        help="Directory where received JSON batches are written.",
    )
    parser.add_argument(
        "--token",
        default="",
        help="Optional bearer token to require in the Authorization header.",
    )
    parser.add_argument(
        "--status",
        type=int,
        default=200,
        help="HTTP status to return after authentication and size checks. Default: 200",
    )
    parser.add_argument(
        "--retry-after",
        type=int,
        default=0,
        help="Retry-After seconds to return with HTTP 429 responses.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="Reject compressed request bodies larger than this many bytes with 413. "
        f"0 disables the cap. Default: {DEFAULT_MAX_BYTES}.",
    )
    parser.add_argument(
        "--max-decompressed-bytes",
        type=int,
        default=DEFAULT_MAX_DECOMPRESSED_BYTES,
        help="Reject gzip bodies that decompress to more than this many bytes with "
        f"413 (decompression-bomb guard). 0 disables the cap. Default: {DEFAULT_MAX_DECOMPRESSED_BYTES}.",
    )
    return parser.parse_args()


def response_body(**values: Any) -> bytes:
    return (json.dumps(values) + "\n").encode("utf-8")


class DecompressedTooLarge(Exception):
    """Raised when a gzip body would decompress past the configured cap."""


def gunzip_bounded(body: bytes, max_decompressed: int) -> bytes:
    """Decompress a gzip body, refusing to allocate more than max_decompressed bytes.

    Uses an incremental zlib decompressor with a per-call output limit so a small
    "gzip bomb" cannot be expanded into an unbounded buffer. max_decompressed <= 0
    disables the cap (falls back to plain gzip.decompress).
    """
    if max_decompressed <= 0:
        return gzip.decompress(body)
    # 16 + MAX_WBITS enables gzip (rather than raw zlib) header handling.
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    # Ask for one byte past the limit so we can distinguish "exactly at cap" from
    # "overflowed"; anything left in unconsumed_tail also means we stopped early.
    out = decompressor.decompress(body, max_decompressed + 1)
    if len(out) > max_decompressed or decompressor.unconsumed_tail:
        raise DecompressedTooLarge(
            f"decompressed body exceeds {max_decompressed} bytes"
        )
    out += decompressor.flush()
    if len(out) > max_decompressed:
        raise DecompressedTooLarge(
            f"decompressed body exceeds {max_decompressed} bytes"
        )
    return out


def decode_body(body: bytes, content_encoding: str, max_decompressed: int) -> bytes:
    if content_encoding.lower() == "gzip":
        return gunzip_bounded(body, max_decompressed)
    return body


def make_handler(
    out_dir: Path,
    expected_token: str,
    forced_status: int,
    retry_after: int,
    max_bytes: int,
    max_decompressed_bytes: int,
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        counter = 0

        def do_POST(self) -> None:
            if expected_token:
                expected_header = f"Bearer {expected_token}"
                actual_header = self.headers.get("Authorization", "")
                if actual_header != expected_header:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(response_body(ok=False, error="unauthorized"))
                    return

            content_length = int(self.headers.get("Content-Length", "0"))
            if max_bytes and content_length > max_bytes:
                self.send_response(413)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(response_body(ok=False, error="request too large"))
                return

            body = self.rfile.read(content_length)
            try:
                decoded_body = decode_body(
                    body,
                    self.headers.get("Content-Encoding", ""),
                    max_decompressed_bytes,
                )
            except DecompressedTooLarge as exc:
                self.send_response(413)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(response_body(ok=False, error=str(exc)))
                return
            except Exception as exc:  # noqa: BLE001 - local test server reports decode failures.
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(response_body(ok=False, error=str(exc)))
                return

            Handler.counter += 1
            output_path = out_dir / f"batch-{Handler.counter:03d}.json"
            output_path.write_bytes(decoded_body)

            try:
                payload = json.loads(decoded_body.decode("utf-8"))
                summary = {
                    "ok": 200 <= forced_status < 300,
                    "file": str(output_path),
                    "status": forced_status,
                    "encoding": self.headers.get("Content-Encoding", ""),
                    "wire_bytes": len(body),
                    "json_bytes": len(decoded_body),
                    "scan_id": payload.get("scan_id"),
                    "batch_index": payload.get("batch_index"),
                    "batch_count": payload.get("batch_count"),
                    "batch_package_count": payload.get("batch_package_count"),
                    "package_count": len(payload.get("packages", [])),
                    "dependency_edge_count": len(payload.get("dependency_edges", [])),
                }
                print(json.dumps(summary), flush=True)
            except Exception as exc:  # noqa: BLE001 - test receiver should report bad payloads.
                summary = {"ok": False, "file": str(output_path), "error": str(exc)}
                print(json.dumps(summary), flush=True)
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(response_body(ok=False, error=str(exc)))
                return

            self.send_response(forced_status)
            self.send_header("Content-Type", "application/json")
            if forced_status == 429 and retry_after > 0:
                self.send_header("Retry-After", str(retry_after))
            self.end_headers()
            self.wfile.write(response_body(ok=200 <= forced_status < 300))

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return Handler


def main() -> int:
    args = parse_args()

    # Refuse to expose this unauthenticated, disk-writing test receiver beyond
    # loopback unless the operator explicitly acknowledges the risk.
    if args.host not in LOOPBACK_HOSTS and not args.allow_insecure_bind:
        print(
            f"refusing to bind non-loopback host {args.host!r}: this is an "
            "unauthenticated test receiver. Use 127.0.0.1, or pass "
            "--i-know-this-is-insecure to override.",
            file=sys.stderr,
        )
        return 2

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    handler = make_handler(
        out_dir=out_dir,
        expected_token=args.token,
        forced_status=args.status,
        retry_after=args.retry_after,
        max_bytes=args.max_bytes,
        max_decompressed_bytes=args.max_decompressed_bytes,
    )
    server = HTTPServer((args.host, args.port), handler)
    print(f"listening=http://{args.host}:{server.server_port}/batches", flush=True)
    print(f"out_dir={out_dir}", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopping", flush=True)
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
