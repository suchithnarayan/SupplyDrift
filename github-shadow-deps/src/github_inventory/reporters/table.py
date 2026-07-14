from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from github_inventory.models import Finding, ScanResult, Severity

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim white",
}


class TableReporter:
    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def report(self, result: ScanResult, *, group_by: str | None = None) -> None:
        result = ScanResult(
            findings=[finding.public_copy() for finding in result.findings],
            files_scanned=result.files_scanned,
            scan_duration_ms=result.scan_duration_ms,
        )
        if not result.findings:
            self.console.print(
                Panel(
                    "[bold green]No shadow dependencies found![/bold green]",
                    title="[bold]github-inventory[/bold]",
                    border_style="green",
                )
            )
            self.console.print(
                f"[dim]Scanned {result.files_scanned} files in {result.scan_duration_ms:.0f}ms[/dim]"
            )
            return

        self._print_banner(result)

        if group_by == "dep":
            self._print_grouped_table(result)
        else:
            self._print_detail_table(result)

        self._print_category_breakdown(result)

    # ------------------------------------------------------------------
    # Banner & category breakdown (shared)
    # ------------------------------------------------------------------

    def _print_banner(self, result: ScanResult) -> None:
        by_sev = result.summary_by_severity()
        parts = []
        for sev in Severity:
            count = by_sev.get(sev.value, 0)
            if count:
                parts.append(f"[{_SEVERITY_STYLE[sev]}]{sev.value.upper()}: {count}[/]")
        self.console.print(
            Panel(
                "  ".join(parts)
                + f"\n\n[dim]Files scanned: {result.files_scanned} | "
                f"Time: {result.scan_duration_ms:.0f}ms | "
                f"Total findings: {len(result.findings)}[/dim]",
                title="[bold]github-inventory scan results[/bold]",
                border_style="red" if result.has_blocking_findings else "yellow",
            )
        )

    def _print_category_breakdown(self, result: ScanResult) -> None:
        by_cat = result.summary_by_category()
        cat_table = Table(title="Findings by Category", show_header=True, box=None)
        cat_table.add_column("Category", style="bold")
        cat_table.add_column("Count", justify="right")
        for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
            cat_table.add_row(cat, str(count))
        self.console.print(cat_table)

    # ------------------------------------------------------------------
    # Default detail table (one row per finding)
    # ------------------------------------------------------------------

    def _print_detail_table(self, result: ScanResult) -> None:
        any_ai = any(f.analysis_source == "ai-assisted" for f in result.findings)
        any_enriched = any(f.enrichment for f in result.findings)

        table = Table(show_header=True, header_style="bold", show_lines=False, expand=True)
        table.add_column("SEV", width=9, no_wrap=True)
        if any_ai:
            table.add_column("Src", width=4, no_wrap=True)
        table.add_column("File", overflow="fold", ratio=2)
        table.add_column("Ln", width=5, justify="right", no_wrap=True)
        table.add_column("Category", width=22, no_wrap=True)
        table.add_column("Dependency / Component", overflow="fold", ratio=2)
        table.add_column("Description", overflow="fold", ratio=3)
        if any_enriched:
            table.add_column("Recommendation", overflow="fold", ratio=2)

        for f in result.findings:
            style = _SEVERITY_STYLE[f.severity]
            row = [Text(f.severity.value.upper(), style=style)]
            if any_ai:
                row.append("AI" if f.analysis_source == "ai-assisted" else "rgx")
            row.extend([
                f.file_path,
                str(f.line_number),
                f.category.value,
                f.extracted_dep,
                f.description,
            ])
            if any_enriched:
                rec = (f.enrichment or {}).get("recommendation", "") if f.enrichment else ""
                row.append(rec)
            table.add_row(*row)

        self.console.print(table)

    # ------------------------------------------------------------------
    # Grouped table (one row per unique dependency)
    # ------------------------------------------------------------------

    def _print_grouped_table(self, result: ScanResult) -> None:
        groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        for f in result.findings:
            groups[(f.extracted_dep, f.pattern_id)].append(f)

        rows: list[tuple[Severity, str, str, int, str, str]] = []
        for (_dep, _pid), findings in groups.items():
            worst = min(findings, key=lambda f: f.severity.sort_order)
            locations = _compact_locations(findings)
            rows.append((
                worst.severity,
                worst.extracted_dep,
                worst.category.value,
                len(findings),
                locations,
                findings[0].description,
            ))

        rows.sort(key=lambda r: (r[0].sort_order, r[1]))

        table = Table(show_header=True, header_style="bold", show_lines=False, expand=True)
        table.add_column("SEV", width=9, no_wrap=True)
        table.add_column("Dependency / Component", overflow="fold", ratio=3)
        table.add_column("Category", width=22, no_wrap=True)
        table.add_column("#", width=4, justify="right", no_wrap=True)
        table.add_column("Locations", overflow="fold", ratio=4)
        table.add_column("Description", overflow="fold", ratio=3)

        for sev, dep, cat, count, locs, desc in rows:
            style = _SEVERITY_STYLE[sev]
            table.add_row(
                Text(sev.value.upper(), style=style),
                dep,
                cat,
                str(count),
                locs,
                desc,
            )

        self.console.print(table)


def _compact_locations(findings: list[Finding]) -> str:
    """Build a compact 'file:line,line | file:line' string from a list of findings."""
    by_file: dict[str, list[int]] = defaultdict(list)
    for f in findings:
        by_file[f.file_path].append(f.line_number)

    parts: list[str] = []
    for fp in sorted(by_file):
        name = PurePosixPath(fp).name
        lines = ",".join(str(ln) for ln in sorted(set(by_file[fp])))
        parts.append(f"{name}:{lines}")
    return " | ".join(parts)
