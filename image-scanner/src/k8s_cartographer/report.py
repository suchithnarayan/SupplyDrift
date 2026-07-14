"""Human-readable summary of a cartography scan (no external dependencies)."""
from __future__ import annotations

from typing import Any

_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def summarize(payload: dict[str, Any]) -> dict[str, Any]:
    assets = payload.get("assets", [])
    findings = payload.get("findings", [])
    by_type: dict[str, int] = {}
    for asset in assets:
        by_type[asset["asset_type"]] = by_type.get(asset["asset_type"], 0) + 1
    by_severity: dict[str, int] = {}
    by_finding_type: dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_finding_type[finding["finding_type"]] = by_finding_type.get(finding["finding_type"], 0) + 1
    return {
        "assets_by_type": by_type,
        "findings_by_severity": by_severity,
        "findings_by_type": by_finding_type,
        "total_assets": len(assets),
        "total_findings": len(findings),
    }


def render_table(payload: dict[str, Any]) -> str:
    summary = summarize(payload)
    lines: list[str] = []
    lines.append("=" * 68)
    lines.append("  Kubernetes Cartography - SupplyDrift Vector 3")
    lines.append("=" * 68)

    at = summary["assets_by_type"]
    lines.append(
        "Assets: "
        + ", ".join(f"{count} {name}" for name, count in sorted(at.items()))
        or "Assets: none"
    )
    fs = summary["findings_by_severity"]
    sev_str = ", ".join(
        f"{sev.upper()}: {fs[sev]}"
        for sev in sorted(fs, key=lambda s: _SEVERITY_ORDER.get(s, 0), reverse=True)
    )
    lines.append(f"Findings: {summary['total_findings']}" + (f"  ({sev_str})" if sev_str else ""))
    lines.append("-" * 68)

    findings = sorted(
        payload.get("findings", []),
        key=lambda f: _SEVERITY_ORDER.get(f["severity"], 0),
        reverse=True,
    )
    if not findings:
        lines.append("No findings.")
    for finding in findings:
        ev = finding.get("evidence", {})
        target = ev.get("name") or ev.get("workload") or ev.get("image") or finding["asset_ref"]
        lines.append(f"[{finding['severity'].upper():8}] {finding['finding_type']:20} {target}")
        lines.append(f"           {finding['title']}")
    lines.append("=" * 68)
    return "\n".join(lines)
