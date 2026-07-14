"""Security (H8): the GitHub PAT must never appear in the git clone argv."""
from __future__ import annotations

import github_inventory.repo_loader as rl


class _Result:
    returncode = 0
    stderr = ""
    stdout = ""


def _capture_run(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs.get("env")
        return _Result()

    monkeypatch.setattr(rl.subprocess, "run", fake_run)
    return captured


def test_token_not_in_argv_but_in_env(monkeypatch):
    captured = _capture_run(monkeypatch)
    rl._clone("https://github.com/org/repo.git", "/tmp/x", token="SECRET-TOKEN-123")

    argv = " ".join(captured["args"])
    assert "SECRET-TOKEN-123" not in argv, "PAT leaked into git clone argv"
    assert "x-access-token@github.com" in argv, "expected the non-secret username in the URL"
    # Token is delivered out-of-band via GIT_ASKPASS reading the child env.
    assert captured["env"]["BINV_GIT_TOKEN"] == "SECRET-TOKEN-123"
    assert captured["env"]["GIT_ASKPASS"]
    assert captured["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_public_clone_has_clean_url_and_no_token_env(monkeypatch):
    captured = _capture_run(monkeypatch)
    rl._clone("https://github.com/org/repo.git", "/tmp/x")  # no token

    argv = " ".join(captured["args"])
    assert "x-access-token" not in argv
    assert captured["env"] is None  # inherits parent env unchanged
