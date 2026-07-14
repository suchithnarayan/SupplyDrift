"""SARIF 2.1.0 reporter for integration with GitHub Code Scanning."""
from __future__ import annotations

import json

from github_inventory import __version__
from github_inventory.models import ScanResult, Severity

_LEVEL_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


class SARIFReporter:
    def report(self, result: ScanResult) -> str:
        rules: dict[str, dict] = {}
        sarif_results: list[dict] = []

        for finding in result.findings:
            f = finding.public_copy()
            if f.pattern_id not in rules:
                rules[f.pattern_id] = {
                    "id": f.pattern_id,
                    "name": _to_camel(f.pattern_id),
                    "shortDescription": {"text": f.description},
                    "fullDescription": {
                        "text": f"Category: {f.category.value}. {f.description}"
                    },
                    "defaultConfiguration": {"level": _LEVEL_MAP[f.severity]},
                    "properties": {
                        "tags": ["supply-chain", "security", f.category.value],
                        "precision": "medium",
                    },
                }

            location: dict = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line_number},
                }
            }
            if f.end_line:
                location["physicalLocation"]["region"]["endLine"] = f.end_line

            message_text = f"{f.description} — extracted: `{f.extracted_dep}`"
            if f.enrichment and f.enrichment.get("recommendation"):
                message_text += f"\n\nRecommendation: {f.enrichment['recommendation']}"

            properties: dict = {
                "extracted_dep": f.extracted_dep,
                "category": f.category.value,
                "severity": f.severity.value,
            }
            if f.analysis_source is not None:
                properties["analysis_source"] = f.analysis_source
            if f.confidence is not None:
                properties["confidence"] = f.confidence
            if f.enrichment is not None:
                properties["enrichment"] = f.enrichment
            if f.sensitive is not None:
                properties["sensitive"] = f.sensitive

            sarif_results.append({
                "ruleId": f.pattern_id,
                "level": _LEVEL_MAP[f.severity],
                "message": {"text": message_text},
                "locations": [location],
                "properties": properties,
            })

        sarif = {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "github-inventory",
                            "version": __version__,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)


def _to_camel(s: str) -> str:
    """Convert kebab-case to CamelCase for SARIF rule names."""
    return "".join(word.capitalize() for word in s.split("-"))
