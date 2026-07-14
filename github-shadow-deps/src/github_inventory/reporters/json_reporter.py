from __future__ import annotations

import json

from github_inventory import __version__
from github_inventory.models import ScanResult


class JSONReporter:
    def report(self, result: ScanResult) -> str:
        output = {
            "version": __version__,
            "tool": "github-inventory",
            "summary": {
                "total_findings": len(result.findings),
                "files_scanned": result.files_scanned,
                "scan_duration_ms": round(result.scan_duration_ms, 1),
                "by_severity": result.summary_by_severity(),
                "by_category": result.summary_by_category(),
            },
            "findings": [f.to_dict() for f in result.findings],
        }
        return json.dumps(output, indent=2)
