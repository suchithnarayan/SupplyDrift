"""Resolves a scan target: either a local path or a GitHub URL to be cloned."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

# GitHub URL patterns we recognise
_GITHUB_URL_RE = re.compile(
    r"^(?:https?://github\.com/|git@github\.com:)([\w.-]+/[\w.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


def is_github_url(target: str) -> bool:
    return bool(_GITHUB_URL_RE.match(target))


@contextmanager
def resolve_repo(target: str, token: str = "", timeout: int = 120) -> Generator[Path, None, None]:
    """
    Context manager that yields a Path to the repository root.

    - If `target` is a local path, yields it directly (no cleanup needed).
    - If `target` looks like a GitHub URL, shallow-clones it to a temp dir,
      yields the clone, then removes the temp dir on exit. Pass a `token` (PAT)
      to clone private repos; omit it to clone public repos anonymously.
    """
    if is_github_url(target):
        tmpdir = tempfile.mkdtemp(prefix="github-inventory-")
        try:
            clone_url = _normalise_clone_url(target)
            _clone(clone_url, tmpdir, token=token, timeout=timeout)
            yield Path(tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    else:
        local = Path(target).expanduser().resolve()
        if not local.exists():
            raise ValueError(f"Path does not exist: {local}")
        if not local.is_dir():
            raise ValueError(f"Path is not a directory: {local}")
        yield local


def _normalise_clone_url(target: str) -> str:
    """Convert shorthand github.com/org/repo or git@... to a full HTTPS URL."""
    m = _GITHUB_URL_RE.match(target)
    if not m:
        return target
    slug = m.group(1)
    return f"https://github.com/{slug}.git"


def _clone(url: str, dest: str, token: str = "", timeout: int = 120) -> None:
    """Shallow clone a git repository (token injected for private repos)."""
    clone_url = url
    env = None
    askpass_path = None
    if token and clone_url.startswith("https://github.com/"):
        # Keep the token OUT of argv (which is world-readable via /proc/<pid>/cmdline).
        # Only the non-secret username goes in the URL; the token is delivered through
        # GIT_ASKPASS, which reads it from the (non-world-readable) child environment.
        clone_url = clone_url.replace("https://", "https://x-access-token@", 1)
        fd, askpass_path = tempfile.mkstemp(prefix="github-inventory-askpass-", suffix=".sh")
        os.write(fd, b'#!/bin/sh\nprintf "%s\\n" "$BINV_GIT_TOKEN"\n')
        os.close(fd)
        os.chmod(askpass_path, 0o700)
        env = {
            **os.environ,
            "GIT_ASKPASS": askpass_path,
            "BINV_GIT_TOKEN": token,
            "GIT_TERMINAL_PROMPT": "0",  # never fall back to an interactive prompt
        }
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", clone_url, dest],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        if result.returncode != 0:
            # Never leak the token in error output.
            stderr = result.stderr.replace(token, "***") if token else result.stderr
            raise RuntimeError(f"git clone failed (exit {result.returncode}):\n{stderr}")
    except FileNotFoundError:
        raise RuntimeError("git is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"git clone timed out after {timeout} seconds for {url}")
    finally:
        if askpass_path:
            try:
                os.unlink(askpass_path)
            except OSError:
                pass
