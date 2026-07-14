"""Tests for grype vulnerability scanning over the SBOM."""
from __future__ import annotations

import json
from conftest import FakeExtractor

from image_scanner.config import ScannerConfig
from image_scanner.core.scanner import ImageScanner, build_platform_payload
from image_scanner.core.vulnscan import (
    GrypeVulnScanner,
    build_vuln_scanner,
    grype_matches_to_cyclonedx,
)
from image_scanner.core import vulnscan
from image_scanner.models import ImageTarget


def test_grype_matches_to_cyclonedx_captures_fix():
    doc = {"matches": [
        {"vulnerability": {"id": "CVE-2019-10744", "severity": "Critical",
                           "fix": {"versions": ["4.17.12"], "state": "fixed"}, "dataSource": "https://nvd"},
         "artifact": {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}},
        # duplicate (grype emits per match-detail) -> deduped by (id, purl)
        {"vulnerability": {"id": "CVE-2019-10744", "severity": "Critical", "fix": {"versions": ["4.17.12"]}},
         "artifact": {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"}},
        {"vulnerability": {"id": "CVE-2022-0001", "severity": "Low", "fix": {"versions": [], "state": "unknown"}},
         "artifact": {"name": "x", "version": "1", "purl": "pkg:npm/x@1"}},
    ]}
    vulns = grype_matches_to_cyclonedx(doc)
    assert len(vulns) == 2  # deduped
    lo = next(v for v in vulns if v["id"] == "CVE-2019-10744")
    assert lo["recommendation"] == "Upgrade lodash to 4.17.12"   # the fix is captured
    assert lo["ratings"][0]["severity"] == "critical"
    assert lo["affects"][0]["ref"] == "pkg:npm/lodash@4.17.15"
    nofix = next(v for v in vulns if v["id"] == "CVE-2022-0001")
    assert nofix["recommendation"] == ""  # no fix available -> blank

GRYPE_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "vulnerabilities": [
        {
            "id": "CVE-2024-0001",
            "source": {"name": "nvd"},
            "ratings": [{"severity": "high", "method": "CVSSv3"}],
            "affects": [{"ref": "pkg:deb/ubuntu/openssl@3.0.2"}],
            "description": "example flaw",
            "recommendation": "upgrade openssl",
        }
    ],
}


class FakeGrype:
    name = "grype"

    def __init__(self, vulns):
        self.vulns = vulns
        self.calls: list = []

    def available(self) -> bool:
        return True

    def scan_sbom(self, sbom):
        self.calls.append(sbom)
        return self.vulns


def test_imagescanner_merges_grype_vulns():
    vulns = GRYPE_CYCLONEDX["vulnerabilities"]
    scanner = ImageScanner(FakeExtractor(), vuln_scanner=FakeGrype(vulns))
    res = scanner.scan(ImageTarget(reference="r", registry="docker.io", repository="library/x"))
    assert res.ok
    assert res.vuln_count == 1
    assert res.cyclonedx["vulnerabilities"][0]["id"] == "CVE-2024-0001"
    payload = build_platform_payload(res)
    assert payload["scan_metadata"]["vulnerability_count"] == 1
    # The grype vuln is extracted into a compact CVE finding linked to the package.
    finding = payload["findings"][0]
    assert finding["title"] == "CVE-2024-0001"
    assert finding["component_ref"] == "pkg:deb/ubuntu/openssl@3.0.2"
    assert finding["severity"] == "high"
    assert finding["fix_recommendation"] == "upgrade openssl"


def test_imagescanner_without_vuln_scanner():
    res = ImageScanner(FakeExtractor()).scan(ImageTarget(reference="r"))
    assert res.vuln_count == 0
    assert "vulnerabilities" not in res.cyclonedx


def test_vuln_scan_failure_keeps_sbom():
    class Broken:
        name = "grype"

        def available(self):
            return True

        def scan_sbom(self, sbom):
            raise RuntimeError("grype db missing")

    res = ImageScanner(FakeExtractor(), vuln_scanner=Broken()).scan(ImageTarget(reference="r"))
    assert res.ok  # SBOM preserved
    assert res.vuln_count == 0
    assert "grype db missing" in res.vuln_error


def test_grype_scan_sbom_parses_output(monkeypatch):
    # grype is invoked with native json (which carries the fix), then converted.
    native = {"matches": [{
        "vulnerability": {"id": "CVE-2024-0001", "severity": "High", "fix": {"versions": ["1.2.4"]}},
        "artifact": {"name": "openssl", "version": "1.2.3", "purl": "pkg:deb/openssl@1.2.3"},
    }]}

    class Completed:
        returncode = 0
        stdout = json.dumps(native)
        stderr = ""

    def fake_run(tool, cmd, **kwargs):
        assert tool == "grype"
        assert cmd[0] == "grype" and cmd[1].startswith("sbom:")
        assert cmd[2:] == ["-o", "json", "-q"]
        assert kwargs["network_policy"].value == "blocked"
        assert kwargs["environment"]["GRYPE_DB_AUTO_UPDATE"] == "false"
        assert cmd[1].removeprefix("sbom:") in kwargs["read_paths"]
        return Completed()

    monkeypatch.setattr(vulnscan.tool_sandbox, "run", fake_run)
    grype = GrypeVulnScanner()
    monkeypatch.setattr(grype, "available", lambda: True)
    vulns = grype.scan_sbom({"bomFormat": "CycloneDX", "components": []})
    assert vulns[0]["id"] == "CVE-2024-0001"
    assert vulns[0]["recommendation"] == "Upgrade openssl to 1.2.4"


def test_build_vuln_scanner_toggle():
    assert build_vuln_scanner(ScannerConfig(scan_vulnerabilities=False)) is None
    assert build_vuln_scanner(ScannerConfig()).name == "grype"
