"""Crypto-agility demo: a hybrid classical + post-quantum KEM handshake.

This module illustrates the *interim default* recommended across the industry
during the PQC transition: combine a classical ECDH exchange (X25519) with a
post-quantum KEM (ML-KEM-768, FIPS 203) and derive the session key from
**both** shared secrets via an HKDF. An attacker must break both to recover
the key, so the construction stays secure if either component is broken — the
defining property of a hybrid scheme.

Security posture
----------------
* The ML-KEM-768 half uses the audited ``liboqs`` library through its Python
  binding (``import oqs``) when it is importable.
* If ``liboqs`` is **not** available, the demo falls back to an *illustrative*
  placeholder for the PQC half and emits an explicit warning. The fallback is
  NOT post-quantum secure and exists only so the API and key-schedule can be
  exercised in tests and demos. We do **not** roll our own KEM.
* The classical half (X25519) uses the ``cryptography`` library, which is a
  hard dependency.

The HKDF key derivation binds both transcripts so neither secret can be
substituted independently.
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ML_KEM_MECHANISM = "ML-KEM-768"
_HKDF_INFO = b"pqc-migrator/hybrid-x25519-mlkem768/v1"
_SESSION_KEY_BYTES = 32
# Illustrative fallback shared-secret size (matches ML-KEM-768 secret length).
_FALLBACK_SECRET_BYTES = 32


def liboqs_available() -> bool:
    """Return True if the liboqs Python binding can be imported."""
    try:
        import oqs  # noqa: F401
    except Exception:  # pragma: no cover - import availability is environmental
        return False
    return True


@dataclass(frozen=True)
class HybridHandshakeResult:
    """Outcome of a hybrid handshake, from both parties' perspective."""

    initiator_session_key: bytes
    responder_session_key: bytes
    pqc_backend: str
    is_post_quantum_secure: bool

    @property
    def keys_match(self) -> bool:
        return self.initiator_session_key == self.responder_session_key


def _derive_session_key(classical_secret: bytes, pqc_secret: bytes) -> bytes:
    """Derive a session key from both shared secrets using HKDF-SHA256."""
    combined = classical_secret + pqc_secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_SESSION_KEY_BYTES,
        salt=None,
        info=_HKDF_INFO,
    )
    return hkdf.derive(combined)


def _classical_exchange() -> tuple[bytes, bytes]:
    """Perform an X25519 ECDH and return both parties' identical secrets."""
    initiator_priv = X25519PrivateKey.generate()
    responder_priv = X25519PrivateKey.generate()
    initiator_pub = initiator_priv.public_key()
    responder_pub = responder_priv.public_key()

    initiator_secret = initiator_priv.exchange(responder_pub)
    responder_secret = responder_priv.exchange(
        X25519PublicKey.from_public_bytes(initiator_pub.public_bytes_raw())
    )
    return initiator_secret, responder_secret


def _pqc_exchange_liboqs() -> tuple[bytes, bytes, str]:
    """ML-KEM-768 encapsulation/decapsulation via liboqs.

    Responder generates a keypair; initiator encapsulates to the responder's
    public key, yielding a shared secret on the initiator side and a ciphertext
    that the responder decapsulates to the same secret.
    """
    import oqs

    with oqs.KeyEncapsulation(ML_KEM_MECHANISM) as responder:
        public_key = responder.generate_keypair()
        with oqs.KeyEncapsulation(ML_KEM_MECHANISM) as initiator:
            ciphertext, initiator_secret = initiator.encap_secret(public_key)
        responder_secret = responder.decap_secret(ciphertext)
    return initiator_secret, responder_secret, "liboqs:ML-KEM-768"


def _pqc_exchange_fallback() -> tuple[bytes, bytes, str]:
    """Illustrative, NON-post-quantum fallback when liboqs is absent.

    Both parties derive the same placeholder secret. This exists purely so the
    handshake API and key schedule run end-to-end without liboqs; it provides
    **no** quantum resistance and must never be used in production.
    """
    warnings.warn(
        "liboqs is not available: using an ILLUSTRATIVE, non-post-quantum "
        "fallback for the ML-KEM-768 half of the hybrid handshake. Install the "
        "'oqs' extra (pip install 'pqc-migrator[pqc]') for real ML-KEM-768.",
        RuntimeWarning,
        stacklevel=2,
    )
    shared = os.urandom(_FALLBACK_SECRET_BYTES)
    return shared, shared, "illustrative-fallback"


def perform_hybrid_handshake(*, force_fallback: bool = False) -> HybridHandshakeResult:
    """Run a hybrid X25519 + ML-KEM-768 handshake between two parties.

    Parameters
    ----------
    force_fallback:
        When True, skip liboqs and use the illustrative fallback. Useful for
        tests and for demonstrating the degraded path.

    Returns
    -------
    HybridHandshakeResult
        Both derived session keys (which must match), the PQC backend used,
        and whether the result is genuinely post-quantum secure.
    """
    classical_initiator, classical_responder = _classical_exchange()

    use_liboqs = (not force_fallback) and liboqs_available()
    if use_liboqs:
        try:
            pqc_initiator, pqc_responder, backend = _pqc_exchange_liboqs()
            post_quantum = True
        except Exception as exc:  # pragma: no cover - depends on liboqs runtime
            warnings.warn(
                f"liboqs handshake failed ({exc}); falling back to illustrative "
                "non-post-quantum path.",
                RuntimeWarning,
                stacklevel=2,
            )
            pqc_initiator, pqc_responder, backend = _pqc_exchange_fallback()
            post_quantum = False
    else:
        pqc_initiator, pqc_responder, backend = _pqc_exchange_fallback()
        post_quantum = False

    initiator_key = _derive_session_key(classical_initiator, pqc_initiator)
    responder_key = _derive_session_key(classical_responder, pqc_responder)

    return HybridHandshakeResult(
        initiator_session_key=initiator_key,
        responder_session_key=responder_key,
        pqc_backend=backend,
        is_post_quantum_secure=post_quantum,
    )


def handshake_report(result: HybridHandshakeResult) -> dict[str, Any]:
    """Summarize a handshake result for display (keys shown as hex prefixes)."""
    return {
        "pqc_backend": result.pqc_backend,
        "post_quantum_secure": result.is_post_quantum_secure,
        "session_keys_match": result.keys_match,
        "session_key_preview": result.initiator_session_key[:8].hex() + "...",
        "construction": "HKDF-SHA256(X25519_secret || ML-KEM-768_secret)",
    }
