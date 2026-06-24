"""Tests for the CLI surface using typer's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pqc_migrator import __version__
from pqc_migrator.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_table_exits_nonzero_on_findings() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES)])
    assert result.exit_code == 1
    assert "PQC001" in result.stdout


def test_scan_no_fail_flag() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES), "--no-fail-on-findings"])
    assert result.exit_code == 0


def test_scan_json_output() -> None:
    result = runner.invoke(
        app, ["scan", str(FIXTURES), "--json", "--no-fail-on-findings"]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["files_scanned"] >= 5


def test_scan_sarif_output() -> None:
    result = runner.invoke(
        app, ["scan", str(FIXTURES), "--sarif", "--no-fail-on-findings"]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["version"] == "2.1.0"


def test_scan_missing_path() -> None:
    result = runner.invoke(app, ["scan", "/no/such/path"])
    assert result.exit_code == 2


def test_scan_clean_dir_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("x = 1\n", "utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_scan_writes_output_file(tmp_path: Path) -> None:
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES),
            "--sarif",
            "-o",
            str(out),
            "--no-fail-on-findings",
        ],
    )
    assert result.exit_code == 0
    assert out.exists()
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_cbom_markdown() -> None:
    result = runner.invoke(app, ["cbom", str(FIXTURES)])
    assert result.exit_code == 0
    assert "Cryptography Bill of Materials" in result.stdout


def test_cbom_json() -> None:
    result = runner.invoke(app, ["cbom", str(FIXTURES), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert "components" in data


def test_cbom_bad_format() -> None:
    result = runner.invoke(app, ["cbom", str(FIXTURES), "--format", "xml"])
    assert result.exit_code == 2


def test_tls_invalid_target() -> None:
    result = runner.invoke(app, ["tls", "::::"])
    assert result.exit_code == 2


def test_tls_success_table(monkeypatch) -> None:
    from pqc_migrator import cli
    from pqc_migrator.tls_scan import TlsScanResult

    fake = TlsScanResult(
        host="example.com",
        port=443,
        ok=True,
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        negotiated_group="X25519MLKEM768",
        key_exchange_quantum_status="hybrid-pqc",
        signature_quantum_status="quantum-resistant",
        cert_signature_algorithm="ML-DSA-65",
        hybrid_pqc_negotiated=True,
        notes=("hybrid PQC negotiated",),
    )
    monkeypatch.setattr(cli, "scan_tls", lambda *a, **k: fake)
    result = runner.invoke(app, ["tls", "example.com:443"])
    assert result.exit_code == 0
    assert "TLSv1.3" in result.stdout
    assert "X25519MLKEM768" in result.stdout


def test_tls_success_json(monkeypatch) -> None:
    from pqc_migrator import cli
    from pqc_migrator.tls_scan import TlsScanResult

    fake = TlsScanResult(host="h", port=443, ok=True, protocol="TLSv1.3")
    monkeypatch.setattr(cli, "scan_tls", lambda *a, **k: fake)
    result = runner.invoke(app, ["tls", "h", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["ok"] is True


def test_tls_unresolvable_host_json() -> None:
    result = runner.invoke(
        app, ["tls", "nonexistent.invalid.example:443", "--timeout", "3", "--json"]
    )
    assert result.exit_code == 2
    assert "ok" in result.stdout


def test_demo_runs() -> None:
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "handshake" in result.stdout.lower()


def test_scan_custom_rules(tmp_path: Path) -> None:
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "rule_id": "C1",
                        "primitive": "RSA",
                        "category": "public-key-encryption",
                        "severity": "critical",
                        "message": "m",
                        "recommendation": "ML-KEM",
                        "patterns": [
                            {"regex": "createECDH", "languages": ["javascript"]}
                        ],
                    }
                ]
            }
        ),
        "utf-8",
    )
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "vulnerable_app.js"),
            "--rules",
            str(rules),
            "--json",
            "--no-fail-on-findings",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert any(f["rule_id"] == "C1" for f in data["findings"])
