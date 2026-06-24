"""Tests for the core data models."""

from __future__ import annotations

from pqc_migrator.models import (
    CryptoCategory,
    Finding,
    ScanResult,
    Severity,
)


def _finding(rule_id: str, severity: Severity, line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        primitive="RSA",
        category=CryptoCategory.PUBLIC_KEY_ENCRYPTION,
        severity=severity,
        file_path="x.py",
        line=line,
        column=1,
        message="m",
        recommendation="r",
    )


def test_severity_rank_ordering() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank
    assert Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.LOW.rank > Severity.INFO.rank


def test_severity_sarif_level_mapping() -> None:
    assert Severity.CRITICAL.sarif_level == "error"
    assert Severity.HIGH.sarif_level == "error"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.LOW.sarif_level == "note"
    assert Severity.INFO.sarif_level == "note"


def test_finding_to_dict() -> None:
    data = _finding("PQC001", Severity.CRITICAL).to_dict()
    assert data["rule_id"] == "PQC001"
    assert data["category"] == "public-key-encryption"
    assert data["severity"] == "critical"


def test_scan_result_counts_and_sorting() -> None:
    findings = (
        _finding("PQC006", Severity.MEDIUM, line=10),
        _finding("PQC001", Severity.CRITICAL, line=5),
        _finding("PQC002", Severity.HIGH, line=1),
    )
    result = ScanResult(root=".", findings=findings, files_scanned=1)
    counts = result.counts_by_severity()
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert counts["medium"] == 1
    ordered = result.sorted_findings()
    assert ordered[0].severity is Severity.CRITICAL
    assert ordered[-1].severity is Severity.MEDIUM


def test_scan_result_to_dict() -> None:
    result = ScanResult(root="/x", findings=(_finding("PQC001", Severity.CRITICAL),))
    data = result.to_dict()
    assert data["root"] == "/x"
    assert data["summary"]["critical"] == 1
    assert len(data["findings"]) == 1


def test_empty_scan_result() -> None:
    result = ScanResult(root=".", findings=())
    assert not result.has_findings
    assert result.counts_by_severity()["critical"] == 0
