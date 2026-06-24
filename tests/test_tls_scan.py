"""Tests for TLS classification logic (no network required)."""

from __future__ import annotations

from pqc_migrator import tls_scan
from pqc_migrator.tls_scan import (
    TlsScanResult,
    classify_group,
    classify_signature,
    scan_tls,
)


class _FakeTls:
    """Minimal stand-in for an SSLSocket context manager."""

    def __init__(self, *, version, cipher, cert, group_value=None):
        self._version = version
        self._cipher = cipher
        self._cert = cert
        self._group_value = group_value

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def version(self):
        return self._version

    def cipher(self):
        return self._cipher

    def getpeercert(self):
        return self._cert

    if True:  # group() is optional on real sockets; provided here.

        def group(self):
            return self._group_value


class _FakeRawSock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeContext:
    def __init__(self, fake_tls):
        self._fake_tls = fake_tls

    def wrap_socket(self, sock, server_hostname=None):
        return self._fake_tls


def test_classify_signature_vulnerable() -> None:
    assert classify_signature("sha256WithRSAEncryption") == "vulnerable"
    assert classify_signature("ecdsa-with-SHA384") == "vulnerable"
    assert classify_signature("sha1WithRSA") == "vulnerable"


def test_classify_signature_pqc() -> None:
    assert classify_signature("ML-DSA-65") == "quantum-resistant"
    assert classify_signature("dilithium3") == "quantum-resistant"
    assert classify_signature("SLH-DSA-SHA2-128s") == "quantum-resistant"


def test_classify_signature_unknown() -> None:
    assert classify_signature("") == "unknown"
    assert classify_signature("mystery-alg") == "unknown"


def test_classify_group_hybrid_pqc() -> None:
    status, hybrid = classify_group("X25519MLKEM768")
    assert status == "hybrid-pqc"
    assert hybrid is True
    status, hybrid = classify_group("x25519_kyber768_draft00")
    assert hybrid is True


def test_classify_group_classical() -> None:
    status, hybrid = classify_group("x25519")
    assert status == "vulnerable"
    assert hybrid is False
    status, _ = classify_group("secp256r1")
    assert status == "vulnerable"


def test_classify_group_unknown() -> None:
    status, hybrid = classify_group("")
    assert status == "unknown"
    assert hybrid is False


def test_scan_tls_rejects_empty_host() -> None:
    result = scan_tls("", 443)
    assert result.ok is False
    assert "empty host" in result.error


def test_scan_tls_rejects_bad_port() -> None:
    result = scan_tls("example.com", 0)
    assert result.ok is False
    assert "invalid port" in result.error
    result = scan_tls("example.com", 70000)
    assert result.ok is False


def test_scan_tls_handles_unresolvable_host() -> None:
    result = scan_tls("nonexistent.invalid.example", 443, timeout=3)
    assert result.ok is False
    assert result.error


def test_tls_result_to_dict() -> None:
    result = TlsScanResult(host="h", port=443, ok=True, protocol="TLSv1.3")
    data = result.to_dict()
    assert data["host"] == "h"
    assert data["protocol"] == "TLSv1.3"
    assert "notes" in data


def _patched_scan(monkeypatch, fake_tls):
    monkeypatch.setattr(
        tls_scan.socket,
        "create_connection",
        lambda *a, **k: _FakeRawSock(),
    )
    monkeypatch.setattr(
        tls_scan.ssl,
        "create_default_context",
        lambda: _FakeContext(fake_tls),
    )


def test_scan_tls_success_classical(monkeypatch) -> None:
    fake = _FakeTls(
        version="TLSv1.3",
        cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        cert={"signatureAlgorithm": "sha256WithRSAEncryption"},
        group_value="x25519",
    )
    _patched_scan(monkeypatch, fake)
    result = scan_tls("example.com", 443)
    assert result.ok is True
    assert result.protocol == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.negotiated_group == "x25519"
    assert result.key_exchange_quantum_status == "vulnerable"
    assert result.signature_quantum_status == "vulnerable"
    assert result.hybrid_pqc_negotiated is False
    assert any("classical" in note for note in result.notes)


def test_scan_tls_success_hybrid_pqc(monkeypatch) -> None:
    fake = _FakeTls(
        version="TLSv1.3",
        cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        cert={"signatureAlgorithm": "ML-DSA-65"},
        group_value="X25519MLKEM768",
    )
    _patched_scan(monkeypatch, fake)
    result = scan_tls("example.com", 443)
    assert result.ok is True
    assert result.hybrid_pqc_negotiated is True
    assert result.key_exchange_quantum_status == "hybrid-pqc"
    assert result.signature_quantum_status == "quantum-resistant"


def test_scan_tls_group_not_exposed_note(monkeypatch) -> None:
    fake = _FakeTls(
        version="TLSv1.3",
        cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        cert={},
        group_value=None,
    )
    _patched_scan(monkeypatch, fake)
    result = scan_tls("example.com", 443)
    assert result.ok is True
    assert result.negotiated_group == ""
    assert any("not exposed" in note for note in result.notes)


def test_scan_tls_cert_verification_error(monkeypatch) -> None:
    import ssl as real_ssl

    err = real_ssl.SSLCertVerificationError("verify failed")
    err.reason = "CERTIFICATE_VERIFY_FAILED"

    class _RaisingContext:
        def wrap_socket(self, sock, server_hostname=None):
            raise err

    monkeypatch.setattr(
        tls_scan.socket, "create_connection", lambda *a, **k: _FakeRawSock()
    )
    monkeypatch.setattr(
        tls_scan.ssl, "create_default_context", lambda: _RaisingContext()
    )
    result = scan_tls("example.com", 443)
    assert result.ok is False
    assert "certificate verification" in result.error


def test_scan_tls_timeout(monkeypatch) -> None:
    def _raise(*a, **k):
        raise TimeoutError()

    monkeypatch.setattr(tls_scan.socket, "create_connection", _raise)
    result = scan_tls("example.com", 443, timeout=1)
    assert result.ok is False
    assert "timed out" in result.error


def test_extract_group_handles_exception(monkeypatch) -> None:
    class _BadGroup:
        def group(self):
            raise ValueError("boom")

    assert tls_scan._extract_negotiated_group(_BadGroup()) == ""  # type: ignore[arg-type]


def test_extract_group_absent() -> None:
    assert tls_scan._extract_negotiated_group(object()) == ""  # type: ignore[arg-type]
