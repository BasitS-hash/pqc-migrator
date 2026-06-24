"""Core data models for pqc-migrator.

These models are intentionally immutable (frozen dataclasses) so that
findings can be safely passed between the scanner, the rule engine, and the
output renderers without any layer mutating shared state.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Quantum-vulnerability severity, framed by Harvest-Now-Decrypt-Later risk.

    HNDL risk is highest for *key establishment* (RSA/ECDH/DH) because traffic
    captured today can be decrypted once a cryptographically relevant quantum
    computer (CRQC) exists. Signatures are forgeable post-CRQC but are not
    retroactively breakable, so they are ranked one tier lower by default.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]

    @property
    def sarif_level(self) -> str:
        """Map to the SARIF 2.1.0 result level vocabulary."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self is Severity.MEDIUM:
            return "warning"
        return "note"


class CryptoCategory(enum.Enum):
    """What the vulnerable primitive is used for, which drives the mapping."""

    KEY_EXCHANGE = "key-exchange"
    SIGNATURE = "signature"
    PUBLIC_KEY_ENCRYPTION = "public-key-encryption"
    HASH = "hash"
    SYMMETRIC = "symmetric"
    CERTIFICATE = "certificate"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Finding:
    """A single quantum-vulnerable cryptography usage detected in a codebase."""

    rule_id: str
    primitive: str
    category: CryptoCategory
    severity: Severity
    file_path: str
    line: int
    column: int
    message: str
    recommendation: str
    cnsa_note: str = ""
    snippet: str = ""
    detector: str = "regex"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "primitive": self.primitive,
            "category": self.category.value,
            "severity": self.severity.value,
            "file": self.file_path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "recommendation": self.recommendation,
            "cnsa_note": self.cnsa_note,
            "snippet": self.snippet,
            "detector": self.detector,
        }


@dataclass(frozen=True)
class ScanResult:
    """Aggregate result of scanning a path."""

    root: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    files_scanned: int = 0
    files_skipped: int = 0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered by severity (desc), then file, then line."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.file_path, f.line),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "summary": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
