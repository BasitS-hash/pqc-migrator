"""Codebase walker that dispatches files to the right scanner.

Maps file extensions to a language, walks a directory tree (skipping common
noise like ``.git`` and virtualenvs), and routes Python files to the precise
AST scanner while everything else goes through the regex text scanner.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from pqc_migrator.models import Finding, ScanResult
from pqc_migrator.rules.engine import RuleEngine
from pqc_migrator.scanners.python_ast import PythonAstScanner
from pqc_migrator.scanners.text import TextScanner

# Extension -> language identifier used by rules.
_EXTENSION_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".yaml": "config",
    ".yml": "config",
    ".toml": "config",
    ".ini": "config",
    ".conf": "config",
    ".cnf": "config",
    ".properties": "config",
    ".env": "config",
    ".pem": "cert",
    ".crt": "cert",
    ".cer": "cert",
    ".key": "cert",
}

# Directories never worth scanning.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".tox",
        "site-packages",
        ".idea",
        ".vscode",
    }
)

# Skip files larger than this to avoid pathological binary/minified inputs.
_MAX_FILE_BYTES = 2_000_000


def language_for_path(path: Path) -> str | None:
    """Return the language identifier for a file path, or None if unsupported."""
    return _EXTENSION_LANGUAGE.get(path.suffix.lower())


class CodebaseScanner:
    """Walks a path and produces a :class:`ScanResult`."""

    def __init__(self, engine: RuleEngine | None = None) -> None:
        self._engine = engine or RuleEngine.with_defaults()
        self._python = PythonAstScanner(self._engine)
        self._text = TextScanner(self._engine)

    def scan_path(self, root: str | Path) -> ScanResult:
        """Scan a file or directory and return aggregated findings."""
        root_path = Path(root)
        if not root_path.exists():
            raise FileNotFoundError(f"Path does not exist: {root_path}")

        findings: list[Finding] = []
        scanned = 0
        skipped = 0

        if root_path.is_file():
            files = [root_path]
        else:
            files = list(self._iter_files(root_path))

        for file_path in files:
            language = language_for_path(file_path)
            if language is None:
                skipped += 1
                continue
            try:
                if file_path.stat().st_size > _MAX_FILE_BYTES:
                    skipped += 1
                    continue
                source = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                skipped += 1
                continue

            display_path = self._display_path(file_path, root_path)
            findings.extend(self._scan_one(source, display_path, language))
            scanned += 1

        return ScanResult(
            root=str(root_path),
            findings=tuple(findings),
            files_scanned=scanned,
            files_skipped=skipped,
        )

    def _scan_one(self, source: str, display_path: str, language: str) -> list[Finding]:
        # Python is scanned structurally via the AST scanner only. Running the
        # regex rules over Python too would reintroduce comment/string false
        # positives, defeating the precision the AST scanner provides.
        if language == "python":
            return self._python.scan(source, display_path)
        return self._text.scan(source, display_path, language)

    @staticmethod
    def _display_path(file_path: Path, root_path: Path) -> str:
        # When a single file is scanned, ``root_path`` *is* the file, so
        # ``relative_to`` would yield "." — useless as a finding location.
        # Report the file's own name in that case.
        if root_path.is_file():
            return file_path.name
        try:
            return str(file_path.relative_to(root_path))
        except ValueError:
            return str(file_path)

    def _iter_files(self, root: Path) -> Iterator[Path]:
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            yield path
