"""Tests for output renderers: JSON, SARIF, table, and CBOM."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from pqc_migrator.output.cbom import (
    build_cbom,
    render_cbom_json,
    render_cbom_markdown,
)
from pqc_migrator.output.json_out import render_json
from pqc_migrator.output.sarif import render_sarif
from pqc_migrator.output.table import render_table
from pqc_migrator.rules.engine import RuleEngine
from pqc_migrator.scanners.walker import CodebaseScanner


def _scan_fixtures(fixtures_dir: Path):
    return CodebaseScanner().scan_path(fixtures_dir)


def test_json_output_is_valid(fixtures_dir: Path) -> None:
    result = _scan_fixtures(fixtures_dir)
    parsed = json.loads(render_json(result))
    assert parsed["files_scanned"] >= 5
    assert "summary" in parsed
    assert len(parsed["findings"]) > 0
    first = parsed["findings"][0]
    assert {"rule_id", "file", "line", "severity"} <= set(first)


def test_sarif_is_valid_2_1_0(fixtures_dir: Path) -> None:
    result = _scan_fixtures(fixtures_dir)
    engine = RuleEngine.with_defaults()
    doc = json.loads(render_sarif(result, engine, version="1.2.3"))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "pqc-migrator"
    assert driver["version"] == "1.2.3"
    assert len(driver["rules"]) >= 9
    # Every result references a valid rule index and uses a SARIF level.
    rule_count = len(driver["rules"])
    for res in run["results"]:
        assert res["level"] in ("error", "warning", "note")
        assert 0 <= res["ruleIndex"] < rule_count
        loc = res["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1
        assert loc["region"]["startColumn"] >= 1


def test_table_renders_findings(fixtures_dir: Path) -> None:
    result = _scan_fixtures(fixtures_dir)
    console = Console(record=True, width=200)
    render_table(result, console)
    text = console.export_text()
    assert "Quantum-Vulnerable Cryptography Findings" in text
    assert "PQC001" in text
    assert "Summary:" in text


def test_table_handles_no_findings(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("x = 1\n", "utf-8")
    result = CodebaseScanner().scan_path(tmp_path)
    console = Console(record=True, width=120)
    render_table(result, console)
    text = console.export_text()
    assert "No quantum-vulnerable cryptography found" in text


def test_cbom_structure(fixtures_dir: Path) -> None:
    result = _scan_fixtures(fixtures_dir)
    cbom = build_cbom(result, generator_version="9.9.9")
    assert cbom["generator"]["version"] == "9.9.9"
    assert cbom["metadata"]["files_scanned"] >= 5
    assert len(cbom["components"]) > 0
    primitives = {c["primitive"] for c in cbom["components"]}
    assert "RSA" in primitives
    # Components are JSON-serializable (no set leakage).
    json.loads(render_cbom_json(cbom))


def test_cbom_markdown_renders(fixtures_dir: Path) -> None:
    result = _scan_fixtures(fixtures_dir)
    cbom = build_cbom(result)
    md = render_cbom_markdown(cbom)
    assert "# Cryptography Bill of Materials" in md
    assert "| Primitive |" in md
    assert "CNSA 2.0" in md


def test_cbom_markdown_empty(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("x = 1\n", "utf-8")
    result = CodebaseScanner().scan_path(tmp_path)
    cbom = build_cbom(result)
    md = render_cbom_markdown(cbom)
    assert "No quantum-vulnerable cryptography detected" in md
