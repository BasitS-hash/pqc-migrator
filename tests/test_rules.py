"""Tests for the rule engine and rule data model."""

from __future__ import annotations

import json

import pytest

from pqc_migrator.models import CryptoCategory, Severity
from pqc_migrator.rules.engine import (
    RuleEngine,
    load_default_rules,
    load_rules_from_file,
)
from pqc_migrator.rules.model import Rule, RulePattern


def test_load_default_rules_returns_rules() -> None:
    rules = load_default_rules()
    assert len(rules) >= 9
    rule_ids = {r.rule_id for r in rules}
    assert {"PQC001", "PQC002", "PQC003", "PQC004", "PQC005"} <= rule_ids


def test_every_default_rule_is_well_formed() -> None:
    for rule in load_default_rules():
        assert rule.rule_id.startswith("PQC")
        assert rule.primitive
        assert rule.recommendation
        assert isinstance(rule.category, CryptoCategory)
        assert isinstance(rule.severity, Severity)


def test_rule_from_dict_validates_required_keys() -> None:
    with pytest.raises(ValueError, match="missing required keys"):
        Rule.from_dict({"rule_id": "X"})


def test_rule_from_dict_rejects_bad_category() -> None:
    with pytest.raises(ValueError, match="invalid category"):
        Rule.from_dict(
            {
                "rule_id": "X",
                "primitive": "P",
                "category": "not-a-category",
                "severity": "high",
                "message": "m",
                "recommendation": "r",
            }
        )


def test_rule_from_dict_rejects_bad_severity() -> None:
    with pytest.raises(ValueError, match="invalid severity"):
        Rule.from_dict(
            {
                "rule_id": "X",
                "primitive": "P",
                "category": "signature",
                "severity": "extreme",
                "message": "m",
                "recommendation": "r",
            }
        )


def test_engine_requires_rules() -> None:
    with pytest.raises(ValueError, match="at least one rule"):
        RuleEngine(())


def test_engine_rule_for_lookup(engine: RuleEngine) -> None:
    rule = engine.rule_for("PQC001")
    assert rule is not None
    assert rule.primitive == "RSA"
    assert engine.rule_for("NOPE") is None


def test_scan_text_detects_go_rsa(engine: RuleEngine) -> None:
    source = "key, _ := rsa.GenerateKey(rand.Reader, 2048)\n"
    findings = engine.scan_text(source, "x.go", "go")
    assert any(f.rule_id == "PQC001" for f in findings)


def test_scan_text_detects_node_async_generate_keypair_rsa(
    engine: RuleEngine,
) -> None:
    # Regression: the pattern used ``Sync?`` (optional trailing 'c'), which only
    # matched generateKeyPairSync and missed the async crypto.generateKeyPair.
    source = "const kp = crypto.generateKeyPair('rsa', { modulusLength: 2048 });\n"
    findings = engine.scan_text(source, "x.js", "javascript")
    assert any(f.rule_id == "PQC001" for f in findings)


def test_scan_text_detects_node_generate_keypair_sync_rsa(engine: RuleEngine) -> None:
    source = "const kp = crypto.generateKeyPairSync('rsa', {});\n"
    findings = engine.scan_text(source, "x.js", "javascript")
    assert any(f.rule_id == "PQC001" for f in findings)


def test_scan_text_detects_node_ec_keypair_generation(engine: RuleEngine) -> None:
    source = "const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });\n"
    findings = engine.scan_text(source, "x.ts", "typescript")
    assert any(f.rule_id == "PQC002" for f in findings)


def test_scan_text_detects_ssh_rsa_host_key_algorithms(engine: RuleEngine) -> None:
    # Regression: SSH RSA references (ssh-rsa, rsa-sha2-*, ssh_host_rsa_2048_key)
    # were not flagged because the size pattern excluded a leading '_' and had
    # no algorithm-name pattern.
    for line in (
        "PubkeyAcceptedAlgorithms ssh-rsa,rsa-sha2-512",
        "HostKey /etc/ssh/ssh_host_rsa_2048_key",
    ):
        findings = engine.scan_text(line, "sshd_config", "config")
        assert any(f.rule_id == "PQC001" for f in findings), line


def test_scan_text_is_language_scoped(engine: RuleEngine) -> None:
    # The Go rsa.GenerateKey pattern should not fire for the 'java' language.
    source = "key, _ := rsa.GenerateKey(rand.Reader, 2048)\n"
    findings = engine.scan_text(source, "x.java", "java")
    assert all(f.rule_id != "PQC001" for f in findings)


def test_scan_text_reports_one_indexed_line_and_column(engine: RuleEngine) -> None:
    source = "\nconst dh = crypto.createDiffieHellman(2048);\n"
    findings = engine.scan_text(source, "x.js", "javascript")
    dh = next(f for f in findings if f.rule_id == "PQC004")
    assert dh.line == 2
    assert dh.column >= 1


def test_load_rules_from_file_roundtrip(tmp_path) -> None:
    data = {
        "rules": [
            {
                "rule_id": "CUSTOM1",
                "primitive": "RSA",
                "category": "public-key-encryption",
                "severity": "critical",
                "message": "custom",
                "recommendation": "ML-KEM",
                "patterns": [{"regex": "RSA", "languages": ["python"]}],
            }
        ]
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    rules = load_rules_from_file(path)
    assert rules[0].rule_id == "CUSTOM1"


def test_load_rules_from_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        load_rules_from_file("does/not/exist.json")


def test_rule_pattern_compiles() -> None:
    pattern = RulePattern(regex=r"\bRSA\b", languages=("python",))
    compiled = pattern.compile()
    assert compiled.search("use RSA here") is not None
