from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from github_inventory import __version__
from github_inventory.config import Config
from github_inventory.engine import ScanEngine
from github_inventory.models import Severity
from github_inventory.repo_loader import resolve_repo
from github_inventory.reporters.json_reporter import JSONReporter
from github_inventory.reporters.sarif import SARIFReporter
from github_inventory.reporters.table import TableReporter

err_console = Console(stderr=True)


@click.group()
@click.version_option(version=__version__, prog_name="github-inventory")
def cli() -> None:
    """Detect shadow dependencies that traditional SCA tools miss.

    Scans a repository for third-party components pulled in through
    direct binary downloads, curl|bash, npx, git clone, unpinned
    GitHub Actions, vendored binaries, and more.
    """


@cli.command()
@click.argument("target", default=".", metavar="PATH_OR_URL")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write output to file (default: stdout).",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="low",
    show_default=True,
    help="Minimum severity level to report.",
)
@click.option(
    "--category", "-c",
    multiple=True,
    help="Only report findings in this category (repeatable). "
         "E.g. --category cicd-tool --category script-installation",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "never"]),
    default="high",
    show_default=True,
    help="Exit with code 1 if any finding is at or above this severity.",
)
@click.option(
    "--config",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to an externally trusted .github-inventory.yml config file.",
)
@click.option(
    "--trust-target-config",
    is_flag=True,
    default=False,
    help="Trust and load TARGET/.github-inventory.yml (may suppress findings).",
)
@click.option(
    "--group-by", "-g",
    type=click.Choice(["none", "dep"]),
    default="none",
    show_default=True,
    help="Group findings. 'dep' consolidates by unique dependency.",
)
@click.option(
    "--width", "-w",
    type=int,
    default=None,
    help="Table output width in columns (default: auto-detect terminal).",
)
@click.option(
    "--ai",
    "ai_enabled",
    is_flag=True,
    default=False,
    help="Enable AI-powered analysis (requires optional runtime AI SDK and API key). "
         "Off by default — base scan stays fully offline.",
)
@click.option(
    "--ai-model",
    type=str,
    default="claude-sonnet-4-6",
    show_default=True,
    help="Runtime AI model ID for --ai mode.",
)
@click.option(
    "--ai-max-files",
    type=int,
    default=20,
    show_default=True,
    help="Cap number of files sent to the LLM in --ai mode.",
)
@click.option(
    "--enrich",
    "enrich_enabled",
    is_flag=True,
    default=False,
    help="Enrich findings with AI-generated context. Requires --ai.",
)
@click.option(
    "--deep-lockfile",
    "deep_lockfile",
    is_flag=True,
    default=False,
    help="Parse package-lock.json / pnpm-lock.yaml / bun.lock for transitive "
         "packages with install hooks. Slower; opt-in.",
)
def scan(
    target: str,
    output_format: str,
    output: str | None,
    severity: str,
    category: tuple[str, ...],
    fail_on: str,
    config: Path | None,
    trust_target_config: bool,
    group_by: str,
    width: int | None,
    ai_enabled: bool,
    ai_model: str,
    ai_max_files: int,
    enrich_enabled: bool,
    deep_lockfile: bool,
) -> None:
    """Scan a repository for shadow dependencies.

    TARGET can be a local directory path (default: current directory)
    or a GitHub URL (e.g. https://github.com/org/repo).

    \b
    Examples:
      github-inventory scan .
      github-inventory scan /path/to/repo --format json
      github-inventory scan https://github.com/org/repo --format sarif -o results.sarif
      github-inventory scan . --severity high --fail-on critical
    """
    if enrich_enabled and not ai_enabled:
        err_console.print("[bold red]Error:[/bold red] --enrich requires --ai")
        sys.exit(2)
    if config is not None and trust_target_config:
        raise click.UsageError("--config and --trust-target-config are mutually exclusive")

    try:
        with resolve_repo(target) as repo_root:
            if config is not None:
                cfg = Config.load(config)
            elif trust_target_config:
                err_console.print(
                    "[bold yellow]Warning:[/bold yellow] trusting target-owned "
                    ".github-inventory.yml; it may suppress or reclassify findings."
                )
                cfg = Config.load_target(repo_root)
            else:
                cfg = Config()
            cfg.ai_enabled = ai_enabled
            cfg.ai_model = ai_model
            cfg.ai_max_files = ai_max_files
            cfg.enrich_enabled = enrich_enabled
            cfg.deep_lockfile = deep_lockfile
            engine = ScanEngine(repo_root, cfg)
            result = engine.run()
    except (ValueError, RuntimeError) as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)

    # Filter by minimum severity
    min_sev = Severity(severity)
    result.findings = [
        f for f in result.findings
        if f.severity.sort_order <= min_sev.sort_order
    ]

    # Filter by category if requested
    if category:
        result.findings = [
            f for f in result.findings
            if f.category.value in category
        ]

    # Render output
    con = Console(width=width) if width else Console()
    if output_format == "table":
        TableReporter(con).report(result, group_by=group_by if group_by != "none" else None)
    elif output_format == "json":
        text = JSONReporter().report(result)
        _write_output(text, output, con)
    elif output_format == "sarif":
        text = SARIFReporter().report(result)
        _write_output(text, output, con)

    # Exit code
    if fail_on != "never":
        fail_sev = Severity(fail_on)
        if any(f.severity.sort_order <= fail_sev.sort_order for f in result.findings):
            sys.exit(1)


def _write_output(text: str, output: str | None, console: Console | None = None) -> None:
    if output:
        path = Path(output)
        path.write_text(text)
        (console or Console()).print(f"[dim]Output written to {path}[/dim]")
    else:
        click.echo(text)
