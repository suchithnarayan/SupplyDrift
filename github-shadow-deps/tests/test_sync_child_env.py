"""Capability and environment policy for the repository SBOM pass."""
from __future__ import annotations

from github_inventory.sync import sbom


def test_extract_repo_sbom_runs_syft_with_exact_sandbox(monkeypatch, tmp_path):
    captured: dict = {}

    class _Completed:
        returncode = 0
        stdout = "{}"
        stderr = ""

    def fake_run(tool, argv, **kwargs):
        captured.update(tool=tool, argv=argv, **kwargs)
        return _Completed()

    monkeypatch.setenv("SUPPLYDRIFT_RUNNER_TOKEN", "sdr_secret")
    monkeypatch.setenv("SUPPLYDRIFT_SECRET_KEY", "fernet-key")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-do-not-inherit")
    monkeypatch.setenv("KUBECONFIG", "/home/app/.kube/config")
    monkeypatch.setenv("DOCKER_CONFIG", "/home/app/.docker")
    monkeypatch.setattr(sbom, "syft_available", lambda *a, **k: True)
    monkeypatch.setattr(sbom.tool_sandbox, "run", fake_run)

    assert sbom.extract_repo_sbom(str(tmp_path), scan_vulnerabilities=False) == {}
    assert captured["tool"] == "syft"
    assert captured["read_paths"] == [str(tmp_path)]
    assert captured["network_policy"].value == "blocked"
    assert captured["environment"] == {"SYFT_CHECK_FOR_APP_UPDATE": "false"}
