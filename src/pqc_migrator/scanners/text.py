"""Text/regex scanner for non-Python languages and config/cert files."""

from __future__ import annotations

from pqc_migrator.models import Finding
from pqc_migrator.rules.engine import RuleEngine


class TextScanner:
    """Applies the regex rule engine to a source string for a language."""

    def __init__(self, engine: RuleEngine) -> None:
        self._engine = engine

    def scan(self, source: str, file_path: str, language: str) -> list[Finding]:
        return self._engine.scan_text(source, file_path, language)
