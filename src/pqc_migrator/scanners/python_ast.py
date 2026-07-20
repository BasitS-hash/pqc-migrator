"""Precise Python scanner built on the standard-library ``ast`` module.

Regex over Python source is noisy: it flags comments, strings, and unrelated
identifiers. The AST scanner instead resolves *call targets* structurally,
so ``rsa.generate_private_key(...)`` is detected as a function call while the
word "rsa" in a comment is ignored. Each match is mapped to a rule_id in the
shared rule pack so remediation text stays consistent across detectors.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from pqc_migrator.models import Finding
from pqc_migrator.rules.engine import RuleEngine


@dataclass(frozen=True)
class _CallSignature:
    """A dotted attribute/function name suffix mapped to a rule."""

    suffix: tuple[str, ...]
    rule_id: str


# Structural call signatures. Each is matched against the *tail* of a dotted
# call expression, e.g. ``cryptography.hazmat...rsa.generate_private_key``
# matches ("rsa", "generate_private_key").
_CALL_SIGNATURES: tuple[_CallSignature, ...] = (
    _CallSignature(("rsa", "generate_private_key"), "PQC001"),
    _CallSignature(("RSA", "generate"), "PQC001"),
    _CallSignature(("ec", "generate_private_key"), "PQC002"),
    _CallSignature(("ec", "ECDH"), "PQC003"),
    _CallSignature(("dsa", "generate_private_key"), "PQC005"),
    _CallSignature(("DSA", "generate"), "PQC005"),
    _CallSignature(("dh", "generate_parameters"), "PQC004"),
    _CallSignature(("dh", "generate_private_key"), "PQC004"),
    _CallSignature(("DH", "new"), "PQC004"),
    _CallSignature(("hashlib", "md5"), "PQC006"),
    _CallSignature(("hashlib", "sha1"), "PQC007"),
)

# ``hashlib.new("md5")`` style string-argument hash construction.
_HASHLIB_NEW_MAP = {
    "md5": "PQC006",
    "sha1": "PQC007",
    "sha-1": "PQC007",
}

# Curve / algorithm names that imply ECDSA/ECDH usage when referenced.
_EC_CURVE_NAMES = {"SECP256R1", "SECP384R1", "SECP521R1", "SECP256K1"}


def _dotted_name(node: ast.AST) -> list[str]:
    """Flatten an attribute/name chain into its dotted parts."""
    parts: list[str] = []
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    parts.reverse()
    return parts


class _Visitor(ast.NodeVisitor):
    def __init__(self, engine: RuleEngine, file_path: str, source_lines: list[str]):
        self._engine = engine
        self._file_path = file_path
        self._lines = source_lines
        self.findings: list[Finding] = []
        # (rule_id, line) pairs already emitted by a *call* match, used to
        # suppress redundant curve-attribute findings for the same statement,
        # e.g. ``ec.generate_private_key(ec.SECP256R1())`` must not report the
        # single key generation twice.
        self._call_finding_keys: set[tuple[str, int]] = set()

    def _snippet(self, lineno: int) -> str:
        index = lineno - 1
        if 0 <= index < len(self._lines):
            return self._lines[index].strip()[:200]
        return ""

    def _emit(self, rule_id: str, node: ast.AST, *, from_call: bool = False) -> None:
        rule = self._engine.rule_for(rule_id)
        if rule is None:
            return
        lineno = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        if from_call:
            self._call_finding_keys.add((rule_id, lineno))
        self.findings.append(
            Finding(
                rule_id=rule.rule_id,
                primitive=rule.primitive,
                category=rule.category,
                severity=rule.severity,
                file_path=self._file_path,
                line=lineno,
                column=col,
                message=rule.message,
                recommendation=rule.recommendation,
                cnsa_note=rule.cnsa_note,
                snippet=self._snippet(lineno),
                detector="python-ast",
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        parts = _dotted_name(node.func)
        if parts:
            for signature in _CALL_SIGNATURES:
                length = len(signature.suffix)
                if tuple(parts[-length:]) == signature.suffix:
                    self._emit(signature.rule_id, node, from_call=True)
                    break
            else:
                self._check_hashlib_new(parts, node)
        self.generic_visit(node)

    def _check_hashlib_new(self, parts: list[str], node: ast.Call) -> None:
        if parts[-2:] != ["hashlib", "new"] and parts[-1:] != ["new"]:
            return
        if parts[-2:-1] not in (["hashlib"], []) and "hashlib" not in parts:
            return
        if not node.args:
            return
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            rule_id = _HASHLIB_NEW_MAP.get(first.value.lower())
            if rule_id:
                self._emit(rule_id, node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Reference to an EC curve (e.g. ec.SECP256R1) implies ECDSA/ECDH.
        if node.attr.upper() in _EC_CURVE_NAMES:
            lineno = getattr(node, "lineno", 1)
            # Skip when a key-generation call on this line already produced the
            # finding — the curve is that call's argument, not a separate use.
            if ("PQC002", lineno) not in self._call_finding_keys:
                self._emit("PQC002", node)
        self.generic_visit(node)


class PythonAstScanner:
    """Scans Python source precisely via the ``ast`` module."""

    language = "python"

    def __init__(self, engine: RuleEngine) -> None:
        self._engine = engine

    def scan(self, source: str, file_path: str) -> list[Finding]:
        """Return findings for a Python source string.

        On a syntax error the file is skipped (no findings) rather than
        crashing the whole scan; callers can treat an empty list as
        "nothing actionable here".
        """
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        visitor = _Visitor(self._engine, file_path, source.splitlines())
        visitor.visit(tree)
        # De-duplicate identical (rule, line, column) findings that can arise
        # when both a call and an attribute reference match on one line.
        seen: set[tuple[str, int, int]] = set()
        unique: list[Finding] = []
        for finding in visitor.findings:
            key = (finding.rule_id, finding.line, finding.column)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique
