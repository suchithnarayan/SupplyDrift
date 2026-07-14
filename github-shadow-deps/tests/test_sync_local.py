"""Local CLI mode: scan a repo path/URL directly to JSON (no platform/config)."""
from __future__ import annotations

import pytest

from github_inventory.sync.config import ScannerConfig
from github_inventory.sync.pipeline import flatten_payload, local_repo_target, run_local


def test_local_repo_target_path(tmp_path):
    d = tmp_path / "myrepo"
    d.mkdir()
    t = local_repo_target(str(d))
    assert t.owner == "local" and t.repo == "myrepo" and t.clone_url == str(d.resolve())


def test_local_repo_target_slug_and_url():
    t = local_repo_target("octocat/Hello-World")
    assert t.full_name == "octocat/Hello-World" and t.clone_url.endswith("octocat/Hello-World.git")
    t = local_repo_target("https://github.com/octocat/Hello-World")
    assert t.full_name == "octocat/Hello-World" and t.owner == "octocat"


def test_local_repo_target_invalid():
    with pytest.raises(ValueError):
        local_repo_target("not a target")


def test_run_local_scans_dir(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v3\n")
    result = run_local([str(tmp_path)], ScannerConfig(scan_sbom=False))  # phantom-deps only (no syft needed)
    assert not result.errors and len(result.results) == 1 and result.results[0].ok
    payload = result.results[0].payload
    assert payload["assets"][0]["asset_type"] == "repository"
    flat = flatten_payload(payload)
    assert {"components", "vulnerabilities", "issues"} <= set(flat)


def test_flatten_payload_repo():
    payload = {
        "assets": [{"asset_type": "repository", "external_id": "github.com/acme/api", "display_name": "acme/api"}],
        "components": [{"ref": "pkg:npm/lodash@4", "name": "lodash", "version": "4", "ecosystem": "npm",
                        "package_manager": "npm", "purl": "pkg:npm/lodash@4"}],
        "findings": [
            {"finding_type": "cve", "component_ref": "pkg:npm/lodash@4", "title": "CVE-1", "severity": "high",
             "fix_recommendation": "Upgrade lodash to 4.17.21"},
            {"finding_type": "cicd-tool", "severity": "high", "title": "actions/checkout@v3",
             "evidence": {"file": "ci.yml", "line": 4}},
        ],
    }
    flat = flatten_payload(payload)
    assert flat["summary"] == {"components": 1, "vulnerabilities": 1, "issues": 1, "malware": 0}
    v = flat["vulnerabilities"][0]
    assert v["package"] == "lodash" and v["fix"].startswith("Upgrade")
    issue = flat["issues"][0]
    assert issue["type"] == "cicd-tool" and issue["file"] == "ci.yml" and issue["line"] == 4
