"""Tests for the codebase walker and the end-to-end fixture scan."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from pqc_migrator.scanners.walker import (
    CodebaseScanner,
    language_for_path,
)


def test_language_for_path() -> None:
    assert language_for_path(Path("a.py")) == "python"
    assert language_for_path(Path("a.ts")) == "typescript"
    assert language_for_path(Path("a.go")) == "go"
    assert language_for_path(Path("a.java")) == "java"
    assert language_for_path(Path("a.yaml")) == "config"
    assert language_for_path(Path("a.pem")) == "cert"
    assert language_for_path(Path("a.unknown")) is None


def test_scan_missing_path_raises(scanner: CodebaseScanner) -> None:
    with pytest.raises(FileNotFoundError):
        scanner.scan_path("/no/such/path/here")


def test_scan_vulnerable_python_fixture(
    scanner: CodebaseScanner, fixtures_dir: Path
) -> None:
    result = scanner.scan_path(fixtures_dir / "vulnerable_app.py")
    rule_ids = {f.rule_id for f in result.findings}
    # The crypto-laden Python fixture must surface RSA, EC, DH, DSA, MD5, SHA1.
    assert {"PQC001", "PQC002", "PQC004", "PQC005", "PQC006", "PQC007"} <= rule_ids
    assert result.has_findings


def test_scan_clean_python_fixture_has_no_findings(
    scanner: CodebaseScanner, fixtures_dir: Path
) -> None:
    result = scanner.scan_path(fixtures_dir / "clean_app.py")
    assert not result.has_findings
    assert result.files_scanned == 1


def test_scan_js_fixture(scanner: CodebaseScanner, fixtures_dir: Path) -> None:
    result = scanner.scan_path(fixtures_dir / "vulnerable_app.js")
    rule_ids = {f.rule_id for f in result.findings}
    assert {"PQC001", "PQC003", "PQC004", "PQC006", "PQC007"} <= rule_ids


def test_scan_go_fixture(scanner: CodebaseScanner, fixtures_dir: Path) -> None:
    result = scanner.scan_path(fixtures_dir / "vulnerable_app.go")
    rule_ids = {f.rule_id for f in result.findings}
    assert {"PQC001", "PQC002", "PQC006"} <= rule_ids


def test_scan_config_fixture(scanner: CodebaseScanner, fixtures_dir: Path) -> None:
    result = scanner.scan_path(fixtures_dir / "sshd_config.conf")
    rule_ids = {f.rule_id for f in result.findings}
    assert "PQC004" in rule_ids  # diffie-hellman


def test_scan_directory_aggregates(
    scanner: CodebaseScanner, fixtures_dir: Path
) -> None:
    result = scanner.scan_path(fixtures_dir)
    assert result.files_scanned >= 5
    counts = result.counts_by_severity()
    assert counts["critical"] > 0
    assert counts["high"] > 0


def test_skips_unsupported_files(scanner: CodebaseScanner, tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("rsa.generate_private_key()", "utf-8")
    result = scanner.scan_path(tmp_path)
    assert result.files_scanned == 0
    assert result.files_skipped >= 1


def test_skips_noise_directories(scanner: CodebaseScanner, tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "evil.js").write_text("crypto.createECDH('prime256v1')", "utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", "utf-8")
    result = scanner.scan_path(tmp_path)
    assert not result.has_findings


def test_sorted_findings_orders_by_severity(
    scanner: CodebaseScanner, fixtures_dir: Path
) -> None:
    result = scanner.scan_path(fixtures_dir)
    ranks = [f.severity.rank for f in result.sorted_findings()]
    assert ranks == sorted(ranks, reverse=True)


def test_single_file_scan_reports_file_name_not_dot(
    scanner: CodebaseScanner, fixtures_dir: Path
) -> None:
    # Regression: scanning a single file reported "." as the location because
    # relative_to(file) yields ".". Findings must carry the real file name.
    result = scanner.scan_path(fixtures_dir / "vulnerable_app.js")
    assert result.has_findings
    paths = {f.file_path for f in result.findings}
    assert paths == {"vulnerable_app.js"}


def test_directory_scan_reports_paths_relative_to_root(
    scanner: CodebaseScanner, fixtures_dir: Path
) -> None:
    result = scanner.scan_path(fixtures_dir)
    js_paths = {f.file_path for f in result.findings if f.file_path.endswith(".js")}
    assert "vulnerable_app.js" in js_paths


def test_default_engine_construction() -> None:
    # CodebaseScanner with no engine uses defaults.
    scanner = CodebaseScanner()
    result = scanner.scan_path(Path(__file__).parent / "fixtures")
    counter = Counter(f.rule_id for f in result.findings)
    assert counter["PQC001"] >= 1
