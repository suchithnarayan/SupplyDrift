"""Trusted per-invocation process reaper used by :mod:`executor`.

This file intentionally uses only the Python standard library and runs outside
the tool's Landlock sandbox. Each invocation has its own subreaper, so cleanup
cannot affect subprocesses launched concurrently by another runner thread.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


class _StopReaper(BaseException):
    pass


def _enable_subreaper() -> None:
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")


def _direct_children() -> set[int]:
    children: set[int] = set()
    if not sys.platform.startswith("linux"):
        return children
    try:
        entries = os.scandir("/proc")
    except OSError:
        return children
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                stat = Path(entry.path, "stat").read_text(encoding="utf-8")
                fields = stat[stat.rfind(")") + 1 :].split()
                if len(fields) >= 2 and int(fields[1]) == os.getpid():
                    children.add(int(entry.name))
            except (OSError, ValueError):
                continue
    return children


def _kill_and_reap(root: subprocess.Popen[bytes] | None) -> bool:
    if root is not None and root.poll() is None:
        try:
            os.killpg(root.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        children = _direct_children()
        if not children:
            return True
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except (ChildProcessError, ProcessLookupError):
                pass
    return not _direct_children()


def _write_status(path: str, *, returncode: int, timed_out: bool, error: str = "") -> None:
    payload = json.dumps(
        {"returncode": returncode, "timed_out": timed_out, "error": error},
        separators=(",", ":"),
    )
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--status", required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        _write_status(args.status, returncode=125, timed_out=False, error="empty command")
        return 125

    root: subprocess.Popen[bytes] | None = None

    def stop(_signum, _frame):
        raise _StopReaper()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        _enable_subreaper()
        root = subprocess.Popen(command, start_new_session=True)
        try:
            returncode = root.wait(timeout=args.timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = 124
        cleaned = _kill_and_reap(root)
        if not cleaned:
            _write_status(
                args.status,
                returncode=125,
                timed_out=timed_out,
                error="process-tree cleanup deadline exceeded",
            )
            return 125
        _write_status(args.status, returncode=returncode, timed_out=timed_out)
        return returncode if 0 <= returncode <= 255 else 125
    except _StopReaper:
        _kill_and_reap(root)
        _write_status(args.status, returncode=125, timed_out=False, error="reaper stopped")
        return 125
    except BaseException as exc:
        _kill_and_reap(root)
        _write_status(args.status, returncode=125, timed_out=False, error=str(exc)[:300])
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
