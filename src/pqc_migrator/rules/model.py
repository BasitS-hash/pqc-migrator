"""Data model for detection rules.

A rule is *data*: it carries the metadata for a finding plus the patterns
that trigger it. Patterns are compiled regexes used by the text-based
scanners; the Python AST scanner uses the rule metadata directly via
structural matches keyed on ``rule_id``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pqc_migrator.models import CryptoCategory, Severity


@dataclass(frozen=True)
class RulePattern:
    """A single regex pattern and the languages it applies to."""

    regex: str
    languages: tuple[str, ...]
    flags: int = re.IGNORECASE

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.regex, self.flags)


@dataclass(frozen=True)
class Rule:
    """A detection rule plus the remediation guidance for matches."""

    rule_id: str
    primitive: str
    category: CryptoCategory
    severity: Severity
    message: str
    recommendation: str
    cnsa_note: str
    patterns: tuple[RulePattern, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        """Build a rule from a plain dict (loaded from JSON/YAML).

        Validates required keys and enum membership so malformed rule data
        fails fast with a clear error rather than silently producing bad
        findings.
        """
        required = (
            "rule_id",
            "primitive",
            "category",
            "severity",
            "message",
            "recommendation",
        )
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError(f"Rule missing required keys: {missing}")

        try:
            category = CryptoCategory(data["category"])
        except ValueError as exc:
            raise ValueError(
                f"Rule {data['rule_id']}: invalid category {data['category']!r}"
            ) from exc

        try:
            severity = Severity(data["severity"])
        except ValueError as exc:
            raise ValueError(
                f"Rule {data['rule_id']}: invalid severity {data['severity']!r}"
            ) from exc

        patterns = tuple(
            RulePattern(
                regex=p["regex"],
                languages=tuple(p.get("languages", ())),
            )
            for p in data.get("patterns", ())
        )

        return cls(
            rule_id=data["rule_id"],
            primitive=data["primitive"],
            category=category,
            severity=severity,
            message=data["message"],
            recommendation=data["recommendation"],
            cnsa_note=data.get("cnsa_note", ""),
            patterns=patterns,
        )
