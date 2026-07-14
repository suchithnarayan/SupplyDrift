"""Collect raw Kubernetes resource objects from a cluster or an offline source.

Three sources are supported, in order of how a real engagement uses them:

* ``live``      - shell out to ``kubectl get <kinds> -A -o json`` (read-only).
* ``json dump`` - a previously captured ``kubectl get ... -o json`` file. This
                  is the offline / CI / air-gapped path and needs no cluster.
* ``manifests`` - a directory of YAML/JSON manifests (GitOps repo, ``helm
                  template`` output, etc.). Requires PyYAML for ``.yaml`` files.

All three normalize down to a flat list of resource dicts (the ``items``).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .models import KUBECTL_RESOURCES

# Platform secrets that kubectl (run against attacker-influenced cluster data)
# has no need for and must not inherit from the runner's environment.
_SENSITIVE_ENV_VARS = ("SUPPLYDRIFT_RUNNER_TOKEN", "SUPPLYDRIFT_SECRET_KEY")


def _child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """A copy of ``os.environ`` with the platform secrets stripped, plus ``extra``.

    Everything else (PATH, HOME, KUBECONFIG, AWS_* for the EKS exec plugin, ...)
    is kept so kubectl and any credential exec plugin still work.
    """
    env = {k: v for k, v in os.environ.items() if k not in _SENSITIVE_ENV_VARS}
    if extra:
        env.update(extra)
    return env


def _resolve_kubeconfig(kubeconfig: str | None) -> str | None:
    """Expand ``~`` and ``$VAR`` in a kubeconfig path.

    kubectl is invoked via subprocess with an argv list (no shell), so a leading
    ``~`` is NOT expanded by the OS — kubectl would then stat a literal
    ``~/.kube/config`` and fail with "no such file or directory". Configs commonly
    write ``~/.kube/config``, so expand it here before passing it on.
    """
    if not kubeconfig:
        return kubeconfig
    return os.path.expanduser(os.path.expandvars(kubeconfig))


def _iter_documents(blob: Any) -> Iterable[dict[str, Any]]:
    """Yield individual resource dicts from any kubectl/manifest shape."""
    if blob is None:
        return
    if isinstance(blob, list):
        for item in blob:
            yield from _iter_documents(item)
        return
    if not isinstance(blob, dict):
        return
    kind = blob.get("kind", "")
    if kind.endswith("List") and "items" in blob:
        for item in blob.get("items") or []:
            yield from _iter_documents(item)
        return
    if "kind" in blob and "apiVersion" in blob:
        yield blob


def collect_from_json(text: str) -> list[dict[str, Any]]:
    """Parse a kubectl JSON dump (List, single object, or concatenated objects)."""
    text = text.strip()
    if not text:
        return []
    try:
        return list(_iter_documents(json.loads(text)))
    except json.JSONDecodeError:
        # Fall back to JSON-lines / concatenated objects.
        decoder = json.JSONDecoder()
        items: list[dict[str, Any]] = []
        idx = 0
        length = len(text)
        while idx < length:
            while idx < length and text[idx] in " \t\r\n":
                idx += 1
            if idx >= length:
                break
            obj, end = decoder.raw_decode(text, idx)
            items.extend(_iter_documents(obj))
            idx = end
        return items


def collect_from_json_file(path: Path) -> list[dict[str, Any]]:
    return collect_from_json(path.read_text(encoding="utf-8"))


def collect_from_manifests(directory: Path) -> list[dict[str, Any]]:
    """Load every .yaml/.yml/.json manifest under a directory."""
    items: list[dict[str, Any]] = []
    dir_resolved = directory.resolve()
    paths = sorted(
        p
        for p in directory.rglob("*")
        if p.is_file()
        and p.suffix.lower() in {".yaml", ".yml", ".json"}
        # Don't follow symlinks out of the manifest directory.
        and not (p.is_symlink() and not p.resolve().is_relative_to(dir_resolved))
    )
    yaml_mod = None
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.lower() == ".json":
            items.extend(collect_from_json(text))
            continue
        if yaml_mod is None:
            try:
                import yaml as yaml_mod  # type: ignore
            except ImportError as exc:  # pragma: no cover - depends on env
                raise RuntimeError(
                    "PyYAML is required to read YAML manifests. "
                    "Install it (pip install pyyaml) or use a JSON dump."
                ) from exc
        for doc in yaml_mod.safe_load_all(text):
            items.extend(_iter_documents(doc))
    return items


def collect_from_cluster(
    kubeconfig: str | None = None,
    context: str | None = None,
    namespace: str | None = None,
    kubectl_bin: str = "kubectl",
    env: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Run ``kubectl get`` against a live cluster (read-only).

    ``env`` is merged into the child environment; EKS uses it so the kubeconfig's
    ``aws eks get-token`` exec plugin inherits the resolved AWS credentials.
    """
    cmd = [kubectl_bin, "get", ",".join(KUBECTL_RESOURCES)]
    if namespace:
        cmd += ["-n", namespace]
    else:
        cmd += ["--all-namespaces"]
    cmd += ["-o", "json", "--show-managed-fields"]
    if kubeconfig:
        cmd += ["--kubeconfig", _resolve_kubeconfig(kubeconfig)]
    if context:
        cmd += ["--context", context]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
            # Strip platform secrets; keep PATH/HOME/AWS_* for the exec plugin.
            env=_child_env(env),
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"'{kubectl_bin}' not found on PATH. Install kubectl or use "
            "--from-json / --manifests for an offline scan."
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"kubectl failed (exit {exc.returncode}): {exc.stderr.strip()}"
        ) from exc
    return collect_from_json(completed.stdout)


def list_contexts(
    kubeconfig: str | None = None,
    kubectl_bin: str = "kubectl",
) -> list[str]:
    """List every context in the kubeconfig (one cluster each). Empty on failure."""
    cmd = [kubectl_bin, "config", "get-contexts", "-o", "name"]
    if kubeconfig:
        cmd += ["--kubeconfig", _resolve_kubeconfig(kubeconfig)]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def detect_cluster_name(
    kubeconfig: str | None = None,
    context: str | None = None,
    kubectl_bin: str = "kubectl",
) -> str:
    """Best-effort cluster name from the current kubectl context."""
    cmd = [kubectl_bin, "config", "current-context"]
    if kubeconfig:
        cmd += ["--kubeconfig", _resolve_kubeconfig(kubeconfig)]
    if context:
        return context
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        name = completed.stdout.strip()
        return name or "kubernetes"
    except (FileNotFoundError, subprocess.SubprocessError):
        return "kubernetes"
