"""Tests for the precise Python AST scanner."""

from __future__ import annotations

from pqc_migrator.rules.engine import RuleEngine
from pqc_migrator.scanners.python_ast import PythonAstScanner


def _scan(source: str) -> list[str]:
    engine = RuleEngine.with_defaults()
    scanner = PythonAstScanner(engine)
    return [f.rule_id for f in scanner.scan(source, "x.py")]


def test_detects_rsa_generate_private_key() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    assert "PQC001" in _scan(src)


def test_detects_pycryptodome_rsa_generate() -> None:
    src = "from Crypto.PublicKey import RSA\nk = RSA.generate(2048)\n"
    assert "PQC001" in _scan(src)


def test_detects_ec_private_key_and_curve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "k = ec.generate_private_key(ec.SECP256R1())\n"
    )
    ids = _scan(src)
    assert ids.count("PQC002") >= 1


def test_detects_ecdh() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\nshared = ec.ECDH()\n"
    )
    assert "PQC003" in _scan(src)


def test_detects_dh_parameters() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import dh\n"
        "p = dh.generate_parameters(generator=2, key_size=2048)\n"
    )
    assert "PQC004" in _scan(src)


def test_detects_dsa() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import dsa\n"
        "k = dsa.generate_private_key(key_size=2048)\n"
    )
    assert "PQC005" in _scan(src)


def test_detects_md5_and_sha1() -> None:
    src = "import hashlib\nhashlib.md5(b'x')\nhashlib.sha1(b'y')\n"
    ids = _scan(src)
    assert "PQC006" in ids
    assert "PQC007" in ids


def test_detects_hashlib_new_md5() -> None:
    src = "import hashlib\nd = hashlib.new('md5')\n"
    assert "PQC006" in _scan(src)


def test_ignores_crypto_words_in_comments_and_strings() -> None:
    src = (
        "# we removed rsa and ecdsa and ecdh and md5 long ago\n"
        "NOTE = 'rsa ecdsa ecdh dsa md5 sha1'\n"
        "x = 1\n"
    )
    assert _scan(src) == []


def test_ignores_strong_hashes() -> None:
    src = "import hashlib\nhashlib.sha384(b'x')\nhashlib.sha512(b'y')\n"
    assert _scan(src) == []


def test_syntax_error_yields_no_findings_not_crash() -> None:
    src = "def broken(:\n    rsa.generate_private_key()\n"
    assert _scan(src) == []


def test_findings_carry_line_numbers() -> None:
    engine = RuleEngine.with_defaults()
    scanner = PythonAstScanner(engine)
    src = "import hashlib\n\nhashlib.md5(b'x')\n"
    findings = scanner.scan(src, "x.py")
    md5 = next(f for f in findings if f.rule_id == "PQC006")
    assert md5.line == 3
    assert md5.detector == "python-ast"
