from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from supplydrift_sandbox import (
    NetworkPolicy,
    SandboxConfigurationError,
    SandboxExecutor,
    SandboxUnavailableError,
)
from supplydrift_sandbox import executor as executor_module


def _completed(argv, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def test_manifest_is_exact_and_never_grants_parent_secrets(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    job = tmp_path / "job"
    job.mkdir()
    SandboxExecutor._prepare_job_root(job)
    executor = SandboxExecutor(mode="off")

    manifest = executor._manifest(
        executable=Path("/usr/bin/true"),
        tool="syft",
        job_root=job,
        read_paths=[repo],
        write_paths=[],
        network_policy=NetworkPolicy.BLOCKED,
        allowed_host=None,
    )

    grants = manifest["filesystem"]["grants"]
    paths = {item["path"] for item in grants}
    assert str(repo.resolve()) in paths
    assert str(job / "work") in paths
    assert "/proc" not in paths and "/proc/1" not in paths
    assert "/run/supplydrift" not in paths
    assert "/home/app/.aws" not in paths
    assert "/home/app/.kube" not in paths
    assert "/home/app/.docker" not in paths
    assert manifest["network"] == {"mode": "blocked"}
    assert manifest["process"]["exec_strategy"] == "direct"


def test_local_fallback_still_uses_minimal_environment(monkeypatch):
    executor = SandboxExecutor(mode="off")
    captured = {}
    for key, value in {
        "SUPPLYDRIFT_RUNNER_TOKEN": "runner-secret",
        "SUPPLYDRIFT_SECRET_KEY": "fernet-secret",
        "AWS_ACCESS_KEY_ID": "AKIA-secret",
        "KUBECONFIG": "/home/app/.kube/config",
        "DOCKER_CONFIG": "/home/app/.docker",
    }.items():
        monkeypatch.setenv(key, value)

    def fake_capture(argv, *, env, timeout, cwd=None):
        captured.update(argv=argv, env=env, cwd=cwd)
        return _completed(argv)

    monkeypatch.setattr(executor, "_popen_capture", fake_capture)
    executor.run(
        "syft",
        ["true"],
        environment={"SYFT_CHECK_FOR_APP_UPDATE": "false"},
    )

    assert captured["env"]["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
    for key in (
        "SUPPLYDRIFT_RUNNER_TOKEN",
        "SUPPLYDRIFT_SECRET_KEY",
        "AWS_ACCESS_KEY_ID",
        "KUBECONFIG",
        "DOCKER_CONFIG",
    ):
        assert key not in captured["env"]
    assert Path(captured["cwd"]).name == "work"


def test_child_credentials_are_redacted_from_stdout_and_stderr(monkeypatch):
    secret = 'pull-token-"quoted"-\\path'
    escaped = json.dumps(secret)[1:-1]
    executor = SandboxExecutor(mode="required")
    executor._ready = True
    executor._nono_path = "/usr/local/bin/nono"
    monkeypatch.setattr(executor, "_proxy_preflight", lambda _: True)

    def fake_capture(argv, *, env, timeout, cwd=None):
        return _completed(
            argv,
            stdout=f'{{"raw":"{secret}","escaped":"{escaped}"}}',
            stderr=f"failed with {secret} / {escaped}",
            returncode=1,
        )

    monkeypatch.setattr(executor, "_popen_capture", fake_capture)
    result = executor.run(
        "syft",
        ["true"],
        environment={
            "SYFT_REGISTRY_AUTH_TOKEN": secret,
            "SYFT_CHECK_FOR_APP_UPDATE": "false",
        },
        network_policy=NetworkPolicy.PROXY,
        allowed_host="registry.example",
    )
    assert secret not in result.stdout and escaped not in result.stdout
    assert secret not in result.stderr and escaped not in result.stderr
    assert "[REDACTED]" in result.stdout and "[REDACTED]" in result.stderr


def test_required_mode_fails_when_nono_is_missing(monkeypatch):
    monkeypatch.setattr(executor_module.shutil, "which", lambda _: None)
    with pytest.raises(SandboxUnavailableError, match="was not found"):
        SandboxExecutor(mode="required").ensure_ready()


def test_preflight_requires_both_filesystem_and_blocked_network_canaries(monkeypatch):
    executor = SandboxExecutor(nono_bin="nono", mode="required")
    called = []
    monkeypatch.setattr(executor_module.shutil, "which", lambda _: "/usr/bin/true")

    def fake_capture(argv, *, env, timeout, cwd=None):
        return _completed(argv, stdout="nono 0.67.1\n")

    monkeypatch.setattr(executor, "_popen_capture", fake_capture)
    monkeypatch.setattr(executor, "_filesystem_canary", lambda *args: called.append("fs"))
    monkeypatch.setattr(
        executor, "_blocked_network_canary", lambda *args: called.append("network")
    )
    assert executor.ensure_ready() is True
    assert called == ["fs", "network"]


def test_nono_version_is_parsed_exactly():
    assert SandboxExecutor._parse_nono_version("nono 0.67.1\n") == "0.67.1"
    assert SandboxExecutor._parse_nono_version("nono 0.67.10\n") == "0.67.10"
    assert SandboxExecutor._parse_nono_version("prefix nono 0.67.1") is None


def test_blocked_job_uses_direct_wrap(monkeypatch, tmp_path):
    executor = SandboxExecutor(mode="required")
    executor._ready = True
    executor._nono_path = "/usr/local/bin/nono"
    captured = {}

    def fake_capture(argv, *, env, timeout, cwd=None):
        captured["argv"] = argv
        config = Path(argv[argv.index("--config") + 1])
        captured["manifest"] = json.loads(config.read_text(encoding="utf-8"))
        return _completed(argv, stdout="{}")

    monkeypatch.setattr(executor, "_popen_capture", fake_capture)
    result = executor.run("grype", ["true"], network_policy=NetworkPolicy.BLOCKED)

    assert result.returncode == 0
    assert "wrap" in captured["argv"] and "run" not in captured["argv"]
    assert captured["manifest"]["network"]["mode"] == "blocked"
    assert captured["manifest"]["process"]["exec_strategy"] == "direct"
    separator = captured["argv"].index("--")
    child_argv = captured["argv"][separator + 1 :]
    assert child_argv[0].endswith("/env")
    assert any(value.endswith("/work/home") and value.startswith("HOME=") for value in child_argv)


def test_proxy_fallback_keeps_filesystem_sandbox_and_emits_diagnostic(
    monkeypatch, caplog
):
    executor = SandboxExecutor(mode="required", network_mode="best-effort")
    executor._ready = True
    executor._nono_path = "/usr/local/bin/nono"
    captured = {}
    monkeypatch.setattr(executor, "_proxy_preflight", lambda _: False)

    def fake_capture(argv, *, env, timeout, cwd=None):
        config = Path(argv[argv.index("--config") + 1])
        captured.update(argv=argv, manifest=json.loads(config.read_text(encoding="utf-8")))
        return _completed(argv)

    monkeypatch.setattr(executor, "_popen_capture", fake_capture)
    with caplog.at_level("WARNING"):
        executor.run(
            "syft",
            ["true"],
            environment={"SYFT_CHECK_FOR_APP_UPDATE": "false"},
            network_policy=NetworkPolicy.PROXY,
            allowed_host="registry.example:443",
        )

    assert "wrap" in captured["argv"]
    assert captured["manifest"]["network"] == {"mode": "unrestricted"}
    event = next(record.sandbox for record in caplog.records if hasattr(record, "sandbox"))
    assert event["filesystem_enforced"] is True
    assert event["network_enforced"] is False
    assert event["network_mode"] == "unrestricted-fallback"
    assert event["target_host"] == "registry.example:443"


def test_supported_proxy_uses_supervised_run(monkeypatch):
    executor = SandboxExecutor(mode="required", network_mode="require")
    executor._ready = True
    executor._nono_path = "/usr/local/bin/nono"
    captured = {}
    monkeypatch.setattr(executor, "_proxy_preflight", lambda _: True)

    def fake_capture(argv, *, env, timeout, cwd=None):
        config = Path(argv[argv.index("--config") + 1])
        captured.update(argv=argv, manifest=json.loads(config.read_text(encoding="utf-8")))
        return _completed(argv)

    monkeypatch.setattr(executor, "_popen_capture", fake_capture)
    executor.run(
        "syft",
        ["true"],
        network_policy=NetworkPolicy.PROXY,
        allowed_host="registry.example",
    )

    assert "run" in captured["argv"] and "wrap" not in captured["argv"]
    assert captured["manifest"]["network"]["allow_domains"] == ["registry.example"]
    assert captured["manifest"]["process"]["exec_strategy"] == "supervised"


def test_registry_proxy_includes_only_known_target_auxiliary_hosts():
    assert SandboxExecutor._proxy_domains("registry.example") == ["registry.example"]
    assert SandboxExecutor._proxy_domains("registry-1.docker.io") == [
        "registry-1.docker.io",
        "auth.docker.io",
        "production.cloudflare.docker.com",
    ]
    assert SandboxExecutor._proxy_domains("ghcr.io") == [
        "ghcr.io",
        "pkg-containers.githubusercontent.com",
    ]
    assert SandboxExecutor._proxy_domains("quay.io") == ["quay.io", "cdn.quay.io"]
    assert SandboxExecutor._proxy_domains(
        "123456789012.dkr.ecr.us-east-1.amazonaws.com"
    ) == [
        "123456789012.dkr.ecr.us-east-1.amazonaws.com",
        "prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com",
    ]


def test_protected_read_and_unexpected_environment_are_rejected(tmp_path):
    executor = SandboxExecutor(mode="off")
    job = tmp_path / "job"
    job.mkdir()
    SandboxExecutor._prepare_job_root(job)
    with pytest.raises(SandboxConfigurationError, match="protected path"):
        executor._manifest(
            executable=Path("/usr/bin/true"),
            tool="syft",
            job_root=job,
            read_paths=["/proc/1/environ"],
            write_paths=[],
            network_policy=NetworkPolicy.BLOCKED,
            allowed_host=None,
        )
    with pytest.raises(SandboxConfigurationError, match="not allowed"):
        executor.run("syft", ["true"], environment={"AWS_ACCESS_KEY_ID": "nope"})
    for ancestor in ("/proc", "/run", "/home", "/opt"):
        with pytest.raises(SandboxConfigurationError):
            executor._manifest(
                executable=Path("/usr/bin/true"),
                tool="syft",
                job_root=job,
                read_paths=[ancestor],
                write_paths=[],
                network_policy=NetworkPolicy.BLOCKED,
                allowed_host=None,
            )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux subreaper contract")
def test_successful_tool_cannot_leave_a_setsid_descendant(tmp_path):
    pid_file = tmp_path / "escaped.pid"
    script = """
import os, pathlib, sys, time
pid_file = pathlib.Path(sys.argv[1])
pid = os.fork()
if pid == 0:
    os.setsid()
    pid_file.write_text(str(os.getpid()), encoding="utf-8")
    os.close(0); os.close(1); os.close(2)
    time.sleep(30)
    os._exit(0)
deadline = time.time() + 2
while not pid_file.exists() and time.time() < deadline:
    time.sleep(0.01)
os._exit(0)
"""
    result = SandboxExecutor._popen_capture(
        [sys.executable, "-c", script, str(pid_file)],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=5,
        cwd=tmp_path,
    )
    assert result.returncode == 0
    escaped_pid = int(pid_file.read_text(encoding="utf-8"))
    for _ in range(50):
        if not Path(f"/proc/{escaped_pid}").exists():
            break
        time.sleep(0.01)
    assert not Path(f"/proc/{escaped_pid}").exists()


def test_per_invocation_reapers_allow_concurrent_jobs(tmp_path):
    script = """
import pathlib, sys, time
mine, other = map(pathlib.Path, sys.argv[1:3])
mine.write_text("ready", encoding="utf-8")
deadline = time.time() + 2
while not other.exists() and time.time() < deadline:
    time.sleep(0.01)
raise SystemExit(0 if other.exists() else 42)
"""
    left = tmp_path / "left.ready"
    right = tmp_path / "right.ready"

    def run(mine, other):
        return SandboxExecutor._popen_capture(
            [sys.executable, "-c", script, str(mine), str(other)],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=5,
            cwd=tmp_path,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, left, right), pool.submit(run, right, left)]
        results = [future.result() for future in futures]
    assert [result.returncode for result in results] == [0, 0]


def test_job_reaper_does_not_kill_unrelated_runner_child(tmp_path):
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        result = SandboxExecutor._popen_capture(
            [sys.executable, "-c", "print('done')"],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout=5,
            cwd=tmp_path,
        )
        assert result.returncode == 0 and result.stdout.strip() == "done"
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux subreaper contract")
def test_reaper_cleans_chain_deeper_than_old_iteration_cap(tmp_path):
    pid_file = tmp_path / "chain.pids"
    ready_file = tmp_path / "chain.ready"
    script = """
import os, pathlib, sys, time
pid_file, ready_file = map(pathlib.Path, sys.argv[1:3])
depth = int(sys.argv[3])
def chain(level):
    with pid_file.open("a", encoding="utf-8") as handle:
        handle.write(str(os.getpid()) + "\\n")
    if level == depth:
        ready_file.write_text("ready", encoding="utf-8")
        time.sleep(30)
        os._exit(0)
    child = os.fork()
    if child == 0:
        chain(level + 1)
    time.sleep(30)
    os._exit(0)
child = os.fork()
if child == 0:
    chain(1)
deadline = time.time() + 5
while not ready_file.exists() and time.time() < deadline:
    time.sleep(0.01)
os._exit(0 if ready_file.exists() else 43)
"""
    result = SandboxExecutor._popen_capture(
        [sys.executable, "-c", script, str(pid_file), str(ready_file), "80"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout=8,
        cwd=tmp_path,
    )
    assert result.returncode == 0
    pids = [int(value) for value in pid_file.read_text(encoding="utf-8").splitlines()]
    assert len(pids) == 80
    assert all(not Path(f"/proc/{pid}").exists() for pid in pids)


@pytest.mark.parametrize("host", ["", "https://registry.example", "user@host", "*.example"])
def test_proxy_host_is_plain_and_cannot_become_a_nono_option(host):
    with pytest.raises(SandboxConfigurationError):
        SandboxExecutor._validated_host(host)
