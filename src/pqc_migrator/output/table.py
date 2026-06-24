"""Rich human-readable table renderer."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from pqc_migrator.models import ScanResult, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_table(result: ScanResult, console: Console | None = None) -> None:
    """Print a findings table plus a summary to the console."""
    console = console or Console()

    if not result.has_findings:
        console.print(
            f"[green]No quantum-vulnerable cryptography found[/green] "
            f"(scanned {result.files_scanned} files)."
        )
        return

    table = Table(
        title="Quantum-Vulnerable Cryptography Findings",
        title_style="bold",
        show_lines=False,
        header_style="bold",
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Primitive", no_wrap=True)
    table.add_column("Location", overflow="fold")
    table.add_column("Recommended PQC migration", overflow="fold")

    for finding in result.sorted_findings():
        style = _SEVERITY_STYLE.get(finding.severity, "")
        table.add_row(
            f"[{style}]{finding.severity.value.upper()}[/{style}]",
            finding.rule_id,
            finding.primitive,
            f"{finding.file_path}:{finding.line}:{finding.column}",
            finding.recommendation,
        )

    console.print(table)
    _print_summary(result, console)


def _print_summary(result: ScanResult, console: Console) -> None:
    counts = result.counts_by_severity()
    parts = []
    for severity in Severity:
        count = counts[severity.value]
        if count:
            style = _SEVERITY_STYLE.get(severity, "")
            parts.append(f"[{style}]{count} {severity.value}[/{style}]")
    summary = ", ".join(parts) if parts else "0"
    console.print(
        f"\n[bold]Summary:[/bold] {summary} "
        f"across {result.files_scanned} files scanned "
        f"({result.files_skipped} skipped)."
    )
