"""Tests for the hybrid crypto-agility handshake demo."""

from __future__ import annotations

import warnings

from pqc_migrator.cryptoagility import (
    handshake_report,
    liboqs_available,
    perform_hybrid_handshake,
)


def test_handshake_keys_match_in_fallback() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        result = perform_hybrid_handshake(force_fallback=True)
    assert result.keys_match
    assert len(result.initiator_session_key) == 32


def test_fallback_is_not_post_quantum_secure_and_warns() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = perform_hybrid_handshake(force_fallback=True)
    assert result.is_post_quantum_secure is False
    assert result.pqc_backend == "illustrative-fallback"
    assert any(issubclass(w.category, RuntimeWarning) for w in caught)


def test_handshake_uses_real_backend_when_available() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        result = perform_hybrid_handshake()
    assert result.keys_match
    if liboqs_available():
        assert result.is_post_quantum_secure is True
        assert "liboqs" in result.pqc_backend
    else:
        assert result.is_post_quantum_secure is False


def test_handshake_report_shape() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        result = perform_hybrid_handshake(force_fallback=True)
    report = handshake_report(result)
    assert report["session_keys_match"] is True
    assert "HKDF-SHA256" in report["construction"]
    assert report["session_key_preview"].endswith("...")


def test_liboqs_available_returns_bool() -> None:
    assert isinstance(liboqs_available(), bool)
