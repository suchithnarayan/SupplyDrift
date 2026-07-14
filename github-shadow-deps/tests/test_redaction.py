"""Credential redaction across every scanner output/persistence boundary."""
from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

from github_inventory.models import Category, Finding, ScanResult, Severity
from github_inventory.redaction import redact_text
from github_inventory.reporters.json_reporter import JSONReporter
from github_inventory.reporters.sarif import SARIFReporter
from github_inventory.reporters.table import TableReporter
from github_inventory.sync.connector import RepoTarget
from github_inventory.sync.mapper import build_payload


CANARY = "supplydrift_secret_canary_93dd58f1"


def _credential_finding() -> Finding:
    return Finding(
        file_path=".npmrc",
        line_number=1,
        category=Category.REGISTRY_CONFIG,
        severity=Severity.HIGH,
        pattern_id="credential-canary",
        matched_text=f"//registry.example/:_authToken={CANARY}",
        extracted_dep=f"https://user:{CANARY}@registry.example/pkg?token={CANARY}",
        description=f"Authorization: Bearer {CANARY}",
        scanner_name="test",
        enrichment={
            "summary": f"api_key={CANARY}",
            "nested": [f"client_secret: {CANARY}"],
        },
        sensitive={
            "redacted": True,
            "kind": "registry-credential",
            "credential_type": "npm-auth-token",
            "host": "registry.example",
        },
    )


def _repo() -> RepoTarget:
    return RepoTarget(
        full_name="acme/example",
        owner="acme",
        repo="example",
        clone_url="https://github.com/acme/example.git",
        html_url="https://github.com/acme/example",
        default_branch="main",
        visibility="private",
    )


def test_public_copy_is_idempotent_and_does_not_mutate_source():
    source = _credential_finding()
    once = source.public_copy()
    twice = once.public_copy()

    assert CANARY in source.extracted_dep
    assert once == twice
    assert CANARY not in repr(once)
    assert "[REDACTED]]" not in repr(twice)


def test_all_reporters_and_platform_payload_redact_canary():
    finding = _credential_finding()
    result = ScanResult(findings=[finding], files_scanned=1)
    cyclonedx = {
        "components": [
            {
                "bom-ref": f"https://user:{CANARY}@registry.example/component",
                "name": f"token={CANARY}",
                "version": "1.0",
                "purl": f"pkg:generic/example@1.0?token={CANARY}",
                "properties": [
                    {
                        "name": "syft:location:0:path",
                        "value": f"https://user:{CANARY}@registry.example/source",
                    }
                ],
            }
        ]
    }

    json_output = JSONReporter().report(result)
    sarif_output = SARIFReporter().report(result)
    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None, width=220)
    TableReporter(console).report(result)
    table_output = stream.getvalue()
    payload = build_payload(_repo(), result, "test-source", cyclonedx=cyclonedx)

    combined = "\n".join(
        [json_output, sarif_output, table_output, json.dumps(payload, sort_keys=True)]
    )
    assert CANARY not in combined
    assert "[REDACTED]" in combined

    json_document = json.loads(json_output)
    sarif_document = json.loads(sarif_output)
    assert json_document["tool"] == "github-inventory"
    assert sarif_document["runs"][0]["tool"]["driver"]["name"] == "github-inventory"
    assert "github-inventory" in table_output

    json_finding = json_document["findings"][0]
    sarif_properties = sarif_document["runs"][0]["results"][0]["properties"]
    platform_finding = payload["findings"][0]
    expected = finding.sensitive
    assert json_finding["sensitive"] == expected
    assert sarif_properties["sensitive"] == expected
    assert platform_finding["evidence"]["sensitive"] == expected

    sbom_component = next(
        component for component in payload["components"] if component["version"] == "1.0"
    )
    assert CANARY not in json.dumps(sbom_component, sort_keys=True)
    assert "[REDACTED]" in json.dumps(sbom_component, sort_keys=True)


def test_to_dict_recursively_redacts_enrichment():
    serialized = json.dumps(_credential_finding().to_dict(), sort_keys=True)
    assert CANARY not in serialized
    assert serialized.count("[REDACTED]") >= 5


def test_output_redaction_covers_bare_well_known_token_formats():
    github_token = "ghp_" + "a" * 36
    npm_token = "npm_" + "b" * 36
    text = f"credentials: {github_token} {npm_token}"

    redacted = redact_text(text)

    assert github_token not in redacted
    assert npm_token not in redacted
    assert redacted.count("[REDACTED]") == 2
