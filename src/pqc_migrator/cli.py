"""Command-line interface for pqc-migrator (typer + rich)."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console

from pqc_migrator import __version__
from pqc_migrator.cryptoagility import handshake_report, perform_hybrid_handshake
from pqc_migrator.output.cbom import (
    build_cbom,
    render_cbom_json,
    render_cbom_markdown,
)
from pqc_migrator.output.json_out import render_json
from pqc_migrator.output.sarif import render_sarif
from pqc_migrator.output.table import render_table
from pqc_migrator.rules.engine import (
    RuleEngine,
    load_default_rules,
    load_rules_from_file,
)
from pqc_migrator.scanners.walker import CodebaseScanner
from pqc_migrator.tls_scan import scan_tls

app = typer.Typer(
    name="pqc-migrator",
    help="Post-Quantum Cryptography readiness scanner & migration toolkit.",
    add_completion=False,
    no_args_is_help=True,
)
_console = Console()
_err_console = Console(stderr=True)

# Exit code returned by `scan` when findings are present (CI gating).
_EXIT_FINDINGS = 1
_EXIT_ERROR = 2


class OutputFormat(StrEnum):
    table = "table"
    json = "json"
    sarif = "sarif"


def _version_callback(value: bool) -> None:
    if value:
        _console.print(f"pqc-migrator {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """pqc-migrator top-level options."""


def _build_engine(rules_file: Path | None) -> RuleEngine:
    if rules_file is not None:
        return RuleEngine(load_rules_from_file(rules_file))
    return RuleEngine(load_default_rules())


@app.command()
def scan(
    path: Path = typer.Argument(..., help="File or directory to scan."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.table,
        "--format",
        "-f",
        help="Output format.",
    ),
    json_out: bool = typer.Option(False, "--json", help="Shortcut for --format json."),
    sarif_out: bool = typer.Option(
        False, "--sarif", help="Shortcut for --format sarif."
    ),
    rules_file: Path | None = typer.Option(
        None, "--rules", help="Custom rule pack (JSON) to use instead of defaults."
    ),
    output_file: Path | None = typer.Option(
        None, "--output", "-o", help="Write output to a file instead of stdout."
    ),
    fail_on_findings: bool = typer.Option(
        True,
        "--fail-on-findings/--no-fail-on-findings",
        help="Exit non-zero when findings are present (CI gating).",
    ),
) -> None:
    """Scan a codebase for quantum-vulnerable cryptography."""
    if not path.exists():
        _err_console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(_EXIT_ERROR)

    try:
        engine = _build_engine(rules_file)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        _err_console.print(f"[red]Error loading rules:[/red] {exc}")
        raise typer.Exit(_EXIT_ERROR) from exc

    scanner = CodebaseScanner(engine)
    try:
        result = scanner.scan_path(path)
    except FileNotFoundError as exc:
        _err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(_EXIT_ERROR) from exc

    fmt = output_format
    if json_out:
        fmt = OutputFormat.json
    elif sarif_out:
        fmt = OutputFormat.sarif

    if fmt is OutputFormat.json:
        rendered = render_json(result)
        _emit(rendered, output_file)
    elif fmt is OutputFormat.sarif:
        rendered = render_sarif(result, engine, version=__version__)
        _emit(rendered, output_file)
    else:
        if output_file is not None:
            file_console = Console(file=output_file.open("w", encoding="utf-8"))
            render_table(result, file_console)
        else:
            render_table(result, _console)

    if fail_on_findings and result.has_findings:
        raise typer.Exit(_EXIT_FINDINGS)


@app.command()
def tls(
    target: str = typer.Argument(..., help="Endpoint as host or host:port."),
    timeout: float = typer.Option(10.0, "--timeout", help="Handshake timeout (s)."),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON."),
) -> None:
    """Connect to a TLS endpoint and classify its quantum-vulnerability."""
    host, port = _parse_target(target)
    if host is None:
        _err_console.print(f"[red]Error:[/red] invalid target: {target}")
        raise typer.Exit(_EXIT_ERROR)

    result = scan_tls(host, port, timeout=timeout)

    if json_out:
        _console.print_json(json.dumps(result.to_dict()))
        if not result.ok:
            raise typer.Exit(_EXIT_ERROR)
        return

    if not result.ok:
        _err_console.print(f"[red]TLS scan failed:[/red] {result.error}")
        raise typer.Exit(_EXIT_ERROR)

    _console.print(f"[bold]TLS scan: {host}:{port}[/bold]")
    _console.print(f"  Protocol:           {result.protocol}")
    _console.print(f"  Cipher:             {result.cipher}")
    _console.print(
        f"  Key exchange group: {result.negotiated_group or '(not exposed)'} "
        f"[{result.key_exchange_quantum_status}]"
    )
    _console.print(
        f"  Cert signature:     "
        f"{result.cert_signature_algorithm or '(not exposed)'} "
        f"[{result.signature_quantum_status}]"
    )
    pq = "yes" if result.hybrid_pqc_negotiated else "no"
    _console.print(f"  Hybrid PQC KEX:     {pq}")
    for note in result.notes:
        _console.print(f"  [dim]note:[/dim] {note}")


@app.command()
def cbom(
    path: Path = typer.Argument(..., help="File or directory to inventory."),
    output_format: str = typer.Option(
        "markdown", "--format", "-f", help="markdown or json."
    ),
    output_file: Path | None = typer.Option(
        None, "--output", "-o", help="Write CBOM to a file."
    ),
) -> None:
    """Emit a Crypto Bill of Materials (CBOM) for a codebase."""
    if not path.exists():
        _err_console.print(f"[red]Error:[/red] path does not exist: {path}")
        raise typer.Exit(_EXIT_ERROR)

    scanner = CodebaseScanner()
    result = scanner.scan_path(path)
    document = build_cbom(result, generator_version=__version__)

    if output_format.lower() == "json":
        rendered = render_cbom_json(document)
    elif output_format.lower() in ("markdown", "md"):
        rendered = render_cbom_markdown(document)
    else:
        _err_console.print(f"[red]Error:[/red] unknown CBOM format: {output_format}")
        raise typer.Exit(_EXIT_ERROR)

    _emit(rendered, output_file)


@app.command()
def demo() -> None:
    """Run the hybrid X25519 + ML-KEM-768 handshake demo."""
    result = perform_hybrid_handshake()
    report = handshake_report(result)
    _console.print("[bold]Hybrid classical + PQC KEM handshake[/bold]")
    for key, value in report.items():
        _console.print(f"  {key}: {value}")
    if not result.is_post_quantum_secure:
        _console.print(
            "[yellow]Warning:[/yellow] liboqs unavailable — this run used the "
            "illustrative non-post-quantum fallback. Install with "
            "'pip install pqc-migrator[pqc]' for real ML-KEM-768."
        )


def _emit(rendered: str, output_file: Path | None) -> None:
    if output_file is not None:
        output_file.write_text(rendered + "\n", encoding="utf-8")
        _console.print(f"[green]Wrote[/green] {output_file}")
    else:
        # Use print() to keep machine-readable output clean of rich markup.
        print(rendered)


def _parse_target(target: str) -> tuple[str | None, int]:
    target = target.strip()
    if not target:
        return None, 0
    if ":" in target:
        host, _, port_str = target.rpartition(":")
        if not host:
            return None, 0
        try:
            port = int(port_str)
        except ValueError:
            return None, 0
        return host, port
    return target, 443


if __name__ == "__main__":
    app()
