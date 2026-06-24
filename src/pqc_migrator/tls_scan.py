"""TLS endpoint scanner: classify quantum-vulnerability of a live handshake.

Connects to ``host:port``, completes a TLS handshake, and reports:
  * the negotiated protocol version and cipher suite
  * the leaf certificate's signature algorithm and public key type
  * a quantum-vulnerability classification for both
  * whether a hybrid PQC key-exchange group (e.g. X25519MLKEM768) appears
    to have been negotiated, when the runtime exposes that information

Network and TLS errors are caught and surfaced as a structured result rather
than raising, so the CLI can report failures gracefully.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Any

# IANA-registered hybrid PQC groups (named groups) for TLS 1.3 key agreement.
# Codepoints: X25519MLKEM768 = 0x11ec, SecP256r1MLKEM768 = 0x11eb,
# SecP384r1MLKEM1024 = 0x11ed (per draft-ietf-tls-ecdhe-mlkem).
_HYBRID_PQC_GROUPS = {
    "x25519mlkem768",
    "x25519kyber768draft00",
    "secp256r1mlkem768",
    "secp384r1mlkem1024",
    "p256_mlkem768",
    "p384_mlkem1024",
}

# Substrings in a certificate signature algorithm that indicate quantum risk.
_VULNERABLE_SIG_TOKENS = ("rsa", "ecdsa", "sha1", "dsa", "md5")
# PQC signature algorithm tokens (FIPS 204 / FIPS 205).
_PQC_SIG_TOKENS = ("ml-dsa", "mldsa", "dilithium", "slh-dsa", "sphincs")

_DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True)
class TlsScanResult:
    """Structured result of a TLS endpoint scan."""

    host: str
    port: int
    ok: bool
    error: str = ""
    protocol: str = ""
    cipher: str = ""
    cert_signature_algorithm: str = ""
    cert_public_key_type: str = ""
    negotiated_group: str = ""
    signature_quantum_status: str = "unknown"
    key_exchange_quantum_status: str = "unknown"
    hybrid_pqc_negotiated: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "ok": self.ok,
            "error": self.error,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "certificate_signature_algorithm": self.cert_signature_algorithm,
            "certificate_public_key_type": self.cert_public_key_type,
            "negotiated_group": self.negotiated_group,
            "signature_quantum_status": self.signature_quantum_status,
            "key_exchange_quantum_status": self.key_exchange_quantum_status,
            "hybrid_pqc_negotiated": self.hybrid_pqc_negotiated,
            "notes": list(self.notes),
        }


def classify_signature(algorithm: str) -> str:
    """Classify a certificate signature algorithm for quantum risk."""
    lowered = algorithm.lower()
    if any(token in lowered for token in _PQC_SIG_TOKENS):
        return "quantum-resistant"
    if any(token in lowered for token in _VULNERABLE_SIG_TOKENS):
        return "vulnerable"
    return "unknown"


def classify_group(group: str) -> tuple[str, bool]:
    """Classify a TLS named group; return (status, is_hybrid_pqc)."""
    lowered = group.lower().replace("_", "").replace("-", "")
    normalized = {g.replace("_", "").replace("-", "") for g in _HYBRID_PQC_GROUPS}
    if lowered in normalized:
        return "hybrid-pqc", True
    if not group:
        return "unknown", False
    classical_tokens = ("x25519", "secp", "prime", "ecdh", "ffdhe")
    if any(token in group.lower() for token in classical_tokens):
        return "vulnerable", False
    return "unknown", False


def _extract_negotiated_group(ssl_sock: ssl.SSLSocket) -> str:
    """Best-effort extraction of the negotiated key-exchange group.

    ``SSLSocket.group()`` is available only on newer Python builds linked
    against a sufficiently recent OpenSSL. When it is absent the information is
    not exposed by the stdlib, so we return an empty string and note the
    limitation upstream rather than guessing.
    """
    group_getter = getattr(ssl_sock, "group", None)
    if callable(group_getter):
        try:
            value = group_getter()
            if value:
                return str(value)
        except (ssl.SSLError, OSError, ValueError):
            return ""
    return ""


def _public_key_type(cert: dict[str, Any]) -> str:
    # The stdlib peer-cert dict is sparse; signatureAlgorithm is not exposed,
    # so we report what is available and note the limitation.
    if not isinstance(cert, dict):
        return ""
    return str(cert.get("subjectPublicKeyInfo", ""))


def scan_tls(
    host: str,
    port: int = 443,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    server_name: str | None = None,
) -> TlsScanResult:
    """Scan a TLS endpoint and classify its quantum-vulnerability.

    Parameters are validated; failures (DNS, timeout, handshake) are returned
    as a non-ok result with an ``error`` message rather than raised.
    """
    if not host:
        return TlsScanResult(host=host, port=port, ok=False, error="empty host")
    if not (0 < port < 65536):
        return TlsScanResult(
            host=host, port=port, ok=False, error=f"invalid port: {port}"
        )

    sni = server_name or host
    context = ssl.create_default_context()
    notes: list[str] = []

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=sni) as tls,
        ):
            protocol = tls.version() or ""
            cipher_info = tls.cipher()
            cipher = cipher_info[0] if cipher_info else ""
            cert = tls.getpeercert() or {}
            group = _extract_negotiated_group(tls)
    except ssl.SSLCertVerificationError as exc:
        notes.append("certificate verification failed; handshake still informative")
        return TlsScanResult(
            host=host,
            port=port,
            ok=False,
            error=f"certificate verification error: {exc.reason}",
            notes=tuple(notes),
        )
    except TimeoutError:
        return TlsScanResult(
            host=host,
            port=port,
            ok=False,
            error=f"connection timed out after {timeout}s",
        )
    except (socket.gaierror, ConnectionError, OSError, ssl.SSLError) as exc:
        return TlsScanResult(
            host=host, port=port, ok=False, error=f"connection failed: {exc}"
        )

    sig_alg = _cert_signature_hint(cert)
    pubkey_type = _public_key_type(cert)
    sig_status = classify_signature(sig_alg) if sig_alg else "unknown"
    group_status, is_hybrid = classify_group(group)

    if not group:
        notes.append(
            "Negotiated key-exchange group not exposed by this Python/OpenSSL "
            "runtime (SSLSocket.group() is unavailable). Use OpenSSL 3.5+ "
            "tooling to confirm whether X25519MLKEM768 was negotiated."
        )
    if sig_status == "vulnerable":
        notes.append(
            "Certificate signature is classical (RSA/ECDSA) — plan ML-DSA "
            "reissuance per CNSA 2.0."
        )
    if is_hybrid:
        notes.append(
            "Hybrid PQC key exchange negotiated — transition-grade protection "
            "against Harvest-Now-Decrypt-Later."
        )

    return TlsScanResult(
        host=host,
        port=port,
        ok=True,
        protocol=protocol,
        cipher=cipher,
        cert_signature_algorithm=sig_alg,
        cert_public_key_type=pubkey_type,
        negotiated_group=group,
        signature_quantum_status=sig_status,
        key_exchange_quantum_status=group_status,
        hybrid_pqc_negotiated=is_hybrid,
        notes=tuple(notes),
    )


def _cert_signature_hint(cert: dict[str, Any]) -> str:
    """Derive a signature-algorithm hint from the stdlib peer-cert dict.

    The stdlib does not expose the signature OID directly, but the issuer
    and key material commonly imply RSA/ECDSA. We infer from available fields
    and otherwise return an empty string (classified as 'unknown').
    """
    if not isinstance(cert, dict):
        return ""
    # ``getpeercert`` does not include signatureAlgorithm; some builds expose
    # it under non-standard keys. Check defensively.
    for key in ("signatureAlgorithm", "sigAlg"):
        value = cert.get(key)
        if isinstance(value, str) and value:
            return value
    return ""
