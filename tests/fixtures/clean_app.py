"""A PQC-ready / quantum-safe fixture that should produce zero findings.

Uses only CNSA 2.0-aligned primitives: AES-256, SHA-384, and (conceptually)
ML-KEM for key establishment. No RSA/ECDSA/ECDH/DH/DSA/MD5/SHA-1.
"""

import hashlib


def strong_hash(data: bytes) -> str:
    # SHA-384 is CNSA 2.0-compliant.
    return hashlib.sha384(data).hexdigest()


def strong_hash_512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


# A comment mentioning rsa and ecdsa should NOT be flagged by the AST scanner.
RSA_NOTE = "We migrated away from rsa and ecdsa already."
