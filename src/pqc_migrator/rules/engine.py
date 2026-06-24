"""Rule engine: loads rules-as-data and applies regex rules to text lines.

The engine is deliberately storage-agnostic. Rules ship as JSON
(:mod:`default_rules.json`) but can be loaded from any dict, enabling users
to supply custom rule packs without touching the scanner code.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path
from typing import Any

from pqc_migrator.models import Finding
from pqc_migrator.rules.model import Rule

_DEFAULT_RULES_RESOURCE = "default_rules.json"


def _load_rules_data(data: dict[str, Any]) -> tuple[Rule, ...]:
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("Rule data must contain a top-level 'rules' list")
    return tuple(Rule.from_dict(item) for item in raw_rules)


def load_default_rules() -> tuple[Rule, ...]:
    """Load the bundled default rule pack shipped with the package."""
    resource = resources.files("pqc_migrator.rules").joinpath(_DEFAULT_RULES_RESOURCE)
    data = json.loads(resource.read_text(encoding="utf-8"))
    return _load_rules_data(data)


def load_rules_from_file(path: str | Path) -> tuple[Rule, ...]:
    """Load a custom rule pack from a JSON file on disk."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Rule file not found: {file_path}")
    data = json.loads(file_path.read_text(encoding="utf-8"))
    return _load_rules_data(data)


class _CompiledRule:
    """A rule with its patterns pre-compiled and indexed by language."""

    __slots__ = ("by_language", "rule")

    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.by_language: dict[str, list[re.Pattern[str]]] = {}
        for pattern in rule.patterns:
            compiled = pattern.compile()
            for language in pattern.languages:
                self.by_language.setdefault(language, []).append(compiled)


class RuleEngine:
    """Applies the regex-based rules to source text, line by line."""

    def __init__(self, rules: tuple[Rule, ...]) -> None:
        if not rules:
            raise ValueError("RuleEngine requires at least one rule")
        self._rules = rules
        self._compiled = [_CompiledRule(rule) for rule in rules]

    @classmethod
    def with_defaults(cls) -> RuleEngine:
        return cls(load_default_rules())

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def rule_for(self, rule_id: str) -> Rule | None:
        for rule in self._rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def scan_text(self, text: str, file_path: str, language: str) -> list[Finding]:
        """Scan a blob of text for the given language, returning findings.

        One finding is emitted per (rule, line) match. Lines are 1-indexed
        and columns are 1-indexed to match editor and SARIF conventions.
        """
        findings: list[Finding] = []
        lines = text.splitlines()
        for compiled in self._compiled:
            patterns = compiled.by_language.get(language)
            if not patterns:
                continue
            rule = compiled.rule
            for line_number, line in enumerate(lines, start=1):
                for pattern in patterns:
                    match = pattern.search(line)
                    if match is None:
                        continue
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            primitive=rule.primitive,
                            category=rule.category,
                            severity=rule.severity,
                            file_path=file_path,
                            line=line_number,
                            column=match.start() + 1,
                            message=rule.message,
                            recommendation=rule.recommendation,
                            cnsa_note=rule.cnsa_note,
                            snippet=line.strip()[:200],
                            detector="regex",
                        )
                    )
                    # One finding per rule per line is enough signal.
                    break
        return findings
