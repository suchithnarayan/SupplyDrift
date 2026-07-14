"""Local CLI mode: scan image refs directly to JSON (no platform/config)."""
from __future__ import annotations

from conftest import FakeExtractor

import image_scanner.pipeline as pipeline
from image_scanner.config import ScannerConfig
from image_scanner.pipeline import flatten_payload, parse_image_ref, run_local


def test_parse_image_ref():
    t = parse_image_ref("nginx:latest")
    assert t.registry == "docker.io" and t.repository == "nginx" and t.tag == "latest"
    t = parse_image_ref("ghcr.io/org/repo:v1")
    assert t.registry == "ghcr.io" and t.repository == "org/repo" and t.tag == "v1"
    t = parse_image_ref("localhost:5000/team/app:1.2")
    assert t.registry == "localhost:5000" and t.repository == "team/app" and t.tag == "1.2"
    t = parse_image_ref("alpine@sha256:abc")
    assert t.digest == "sha256:abc" and t.registry == "docker.io" and t.repository == "alpine"


def test_run_local_builds_payloads(monkeypatch):
    monkeypatch.setattr(pipeline, "build_extractor", lambda cfg: FakeExtractor())
    monkeypatch.setattr(pipeline, "build_vuln_scanner", lambda cfg: None)
    result = run_local(["nginx:latest", "alpine:3.19"], ScannerConfig())
    assert len(result.payloads) == 2 and not result.errors
    assert result.payloads[0]["assets"][0]["asset_type"] == "container_image"


def test_flatten_payload():
    payload = {
        "assets": [{"asset_type": "container_image", "external_id": "img:x", "display_name": "x"}],
        "components": [{"ref": "pkg:deb/openssl@1", "name": "openssl", "version": "1", "ecosystem": "deb",
                        "package_manager": "deb", "purl": "pkg:deb/openssl@1", "license": "MIT"}],
        "findings": [{"finding_type": "cve", "component_ref": "pkg:deb/openssl@1", "title": "CVE-1",
                      "severity": "high", "fix_recommendation": "Upgrade openssl to 2"}],
    }
    r = flatten_payload(payload)
    assert r["target"] == "img:x" and r["summary"] == {"components": 1, "vulnerabilities": 1, "malware": 0}
    assert r["components"][0]["name"] == "openssl" and r["components"][0]["license"] == "MIT"
    v = r["vulnerabilities"][0]
    assert v["id"] == "CVE-1" and v["package"] == "openssl" and v["version"] == "1"
    assert v["fix"] == "Upgrade openssl to 2"


def test_cli_local_writes_json(monkeypatch, tmp_path):
    from image_scanner.cli import main

    monkeypatch.setattr(pipeline, "build_extractor", lambda cfg: FakeExtractor())
    monkeypatch.setattr(pipeline, "build_vuln_scanner", lambda cfg: None)
    out = tmp_path / "out.json"
    rc = main(["nginx:latest", "-o", str(out), "-q"])
    assert rc == 0 and out.exists()
    import json
    data = json.loads(out.read_text())
    assert isinstance(data, list) and data[0]["assets"][0]["asset_type"] == "container_image"
    # --report variant
    out2 = tmp_path / "report.json"
    assert main(["nginx:latest", "-o", str(out2), "--report", "-q"]) == 0
    report = json.loads(out2.read_text())
    assert "components" in report[0] and "vulnerabilities" in report[0]
