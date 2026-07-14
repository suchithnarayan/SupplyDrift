"""Regression: a ``~``/``$VAR`` kubeconfig path must be expanded before kubectl.

kubectl runs via subprocess with an argv list (no shell), so a literal ``~`` is
never expanded by the OS — kubectl would stat ``~/.kube/config`` and fail with
"no such file or directory". The collector expands it first.
"""
from __future__ import annotations

from k8s_cartographer import collector


class _Result:
    def __init__(self, stdout: str = '{"items": []}'):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


def _capture_run(monkeypatch, result: _Result) -> dict:
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return result

    monkeypatch.setattr(collector.subprocess, "run", fake_run)
    return captured


def _kubeconfig_arg(cmd: list[str]) -> str:
    return cmd[cmd.index("--kubeconfig") + 1]


def test_collect_from_cluster_expands_tilde(monkeypatch):
    monkeypatch.setenv("HOME", "/home/testuser")
    captured = _capture_run(monkeypatch, _Result())
    collector.collect_from_cluster(kubeconfig="~/.kube/config")
    arg = _kubeconfig_arg(captured["cmd"])
    assert arg == "/home/testuser/.kube/config" and "~" not in arg


def test_collect_from_cluster_expands_env_var(monkeypatch):
    monkeypatch.setenv("HOME", "/home/testuser")
    captured = _capture_run(monkeypatch, _Result())
    collector.collect_from_cluster(kubeconfig="$HOME/.kube/config")
    assert _kubeconfig_arg(captured["cmd"]) == "/home/testuser/.kube/config"


def test_list_contexts_expands_tilde(monkeypatch):
    monkeypatch.setenv("HOME", "/home/testuser")
    captured = _capture_run(monkeypatch, _Result("ctx-a\nctx-b\n"))
    collector.list_contexts(kubeconfig="~/.kube/config")
    assert _kubeconfig_arg(captured["cmd"]) == "/home/testuser/.kube/config"


def test_absolute_path_is_unchanged(monkeypatch):
    captured = _capture_run(monkeypatch, _Result())
    collector.collect_from_cluster(kubeconfig="/etc/k8s/admin.conf")
    assert _kubeconfig_arg(captured["cmd"]) == "/etc/k8s/admin.conf"
