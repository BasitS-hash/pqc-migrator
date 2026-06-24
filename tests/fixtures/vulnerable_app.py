"""Deliberately quantum-vulnerable Python fixture for scanner tests.

This file is intentionally crypto-laden. It is NOT used at runtime by the
package; it exists only so the AST scanner has real, parseable structures to
detect. Do not import or execute it in production.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, rsa


def make_rsa_key():
    # PQC001: RSA key generation (quantum-vulnerable, Shor).
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ec_key():
    # PQC002: ECDSA/ECDH via EC private key on a NIST curve.
    return ec.generate_private_key(ec.SECP256R1())


def make_dsa_key():
    # PQC005: DSA signature key.
    return dsa.generate_private_key(key_size=2048)


def make_dh_params():
    # PQC004: finite-field Diffie-Hellman parameters.
    return dh.generate_parameters(generator=2, key_size=2048)


def weak_md5(data: bytes) -> str:
    # PQC006: MD5 hash.
    return hashlib.md5(data).hexdigest()


def weak_sha1(data: bytes) -> str:
    # PQC007: SHA-1 hash.
    return hashlib.sha1(data).hexdigest()


def weak_via_new(data: bytes) -> str:
    # PQC006 via hashlib.new("md5").
    digest = hashlib.new("md5")
    digest.update(data)
    return digest.hexdigest()
