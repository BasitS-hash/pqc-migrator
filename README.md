# pqc-migrator

> Find the quantum-vulnerable cryptography in your codebase — then map every finding to its NIST PQC replacement.

[![CI](https://github.com/BasitS-hash/pqc-migrator/actions/workflows/ci.yml/badge.svg)](https://github.com/BasitS-hash/pqc-migrator/actions/workflows/ci.yml)
[![CodeQL](https://github.com/BasitS-hash/pqc-migrator/actions/workflows/codeql.yml/badge.svg)](https://github.com/BasitS-hash/pqc-migrator/actions/workflows/codeql.yml)
[![Security scan](https://github.com/BasitS-hash/pqc-migrator/actions/workflows/security.yml/badge.svg)](https://github.com/BasitS-hash/pqc-migrator/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-checked-2a6db2.svg)](https://mypy-lang.org/)

**pqc-migrator** is a Post-Quantum Cryptography (PQC) readiness scanner and migration toolkit. It walks a codebase, flags the cryptography that a future quantum computer will break, classifies each finding by its real-world risk, and tells you exactly which NIST-standardized PQC algorithm to migrate to.

---

## The problem: Harvest Now, Decrypt Later (HNDL)

Quantum computers do not need to exist *yet* to threaten today's encryption. An adversary can **record encrypted traffic now** and decrypt it later, once a cryptographically relevant quantum computer (CRQC) is available. Shor's algorithm breaks the math underpinning RSA, ECDH, ECDSA, DSA, and finite-field Diffie-Hellman — the algorithms that protect almost all key establishment and digital signatures in use today.

This makes **key establishment** the highest-priority migration target: a session key negotiated with ECDH today can be recovered from a captured transcript years from now. Signatures are not retroactively forgeable, so they rank one tier lower — but still need migrating before a CRQC arrives.

In August 2024, NIST finalized the first three PQC standards, and the NSA's CNSA 2.0 suite sets concrete migration deadlines in the 2030–2033 window. The migration is no longer optional or hypothetical — it is a dated compliance requirement. The hard part is **knowing where your vulnerable crypto actually lives.** That is what pqc-migrator does.

---

## Features

- **`scan`** — static analysis that walks a codebase and flags quantum-vulnerable cryptography:
  - **Python via the `ast` module** for precision (a call to `rsa.generate_private_key()` is flagged; the word "rsa" in a comment is not).
  - **Regex rule engine** for JavaScript/TypeScript, Go, Java, and config/certificate files.
  - Every finding reports `file:line:col`, the vulnerable primitive, an HNDL-risk severity, and the recommended PQC/hybrid replacement.
  - A **pluggable rule engine** — rules are data (JSON), so you can ship your own rule pack with `--rules`.
- **`tls`** — connect to a live TLS endpoint, report the certificate signature algorithm and negotiated key-exchange group, classify quantum-vulnerability, and detect whether a hybrid PQC group (e.g. `X25519MLKEM768`) was negotiated.
- **`cbom`** — emit a **Crypto Bill of Materials** (JSON + Markdown) summarizing all crypto usage found.
- **`demo`** — a hybrid classical + post-quantum KEM handshake (X25519 + ML-KEM-768) using `liboqs`, with a clearly-labeled illustrative fallback when `liboqs` is not installed.
- **Output formats**: a rich human table (default), `--json`, and `--sarif` (valid **SARIF 2.1.0** for GitHub code scanning).

---

## Install

```bash
# From source (until published to PyPI)
git clone https://github.com/BasitS-hash/pqc-migrator.git
cd pqc-migrator
pip install -e .

# With the real post-quantum KEM backend (liboqs)
pip install -e ".[pqc]"

# For development (tests, linting, type-checking, security tools)
pip install -e ".[dev]"
```

Requires Python 3.11+.

---

## Usage

### Scan a codebase

`scan` accepts either a directory (walked recursively, skipping VCS/venv/build
noise) or a single file:

```bash
pqc-migrator scan ./my-project        # walk a whole tree
pqc-migrator scan ./keys/issue.py     # scan one file
```

```
                    Quantum-Vulnerable Cryptography Findings
┏━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Rule   ┃ Primitive ┃ Location              ┃ Recommended PQC migration ┃
┡━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ PQC003 │ ECDH      │ tls/handshake.js:9:14 │ Adopt hybrid              │
│          │        │           │                       │ X25519+ML-KEM-768 …       │
│ CRITICAL │ PQC001 │ RSA       │ keys/issue.py:12:11   │ Migrate to ML-KEM-768 …   │
│ HIGH     │ PQC002 │ ECDSA     │ sign.go:18:9          │ Migrate signing to ML-DSA │
└──────────┴────────┴───────────┴───────────────────────┴───────────────────────────┘

Summary: 2 critical, 1 high across 14 files scanned (3 skipped).
```

`scan` exits non-zero when findings are present, so it gates CI by default (use `--no-fail-on-findings` to disable).

```bash
# JSON output
pqc-migrator scan ./my-project --json

# SARIF for GitHub code scanning
pqc-migrator scan ./my-project --sarif -o pqc.sarif

# Use a custom rule pack
pqc-migrator scan ./my-project --rules ./my-rules.json
```

### Inspect a TLS endpoint

```bash
pqc-migrator tls example.com:443
```

```
TLS scan: example.com:443
  Protocol:           TLSv1.3
  Cipher:             TLS_AES_256_GCM_SHA384
  Key exchange group: X25519MLKEM768 [hybrid-pqc]
  Cert signature:     sha256WithRSAEncryption [vulnerable]
  Hybrid PQC KEX:     yes
  note: Hybrid PQC key exchange negotiated — transition-grade protection
        against Harvest-Now-Decrypt-Later.
```

> Detecting the negotiated key-exchange group requires a Python build linked against a recent OpenSSL exposing `SSLSocket.group()`. When that information is not available, pqc-migrator says so explicitly rather than guessing.

### Generate a Crypto Bill of Materials

```bash
pqc-migrator cbom ./my-project                  # Markdown (default)
pqc-migrator cbom ./my-project -f json -o cbom.json
```

### Run the hybrid handshake demo

```bash
pqc-migrator demo
```

---

## Algorithm mapping table

| Vulnerable algorithm | Category | HNDL severity | NIST PQC replacement | CNSA 2.0 note |
| --- | --- | --- | --- | --- |
| **RSA** | Public-key encryption / key transport | Critical | **ML-KEM-768** (FIPS 203), hybrid X25519+ML-KEM-768 in transition | Not approved for NSS after transition |
| **ECDH** | Key exchange | Critical | **ML-KEM-768** (FIPS 203); hybrid `X25519MLKEM768` (codepoint `0x11ec`) interim | ML-KEM mandated for key establishment |
| **DH** (finite-field) | Key exchange | Critical | **ML-KEM-768** (FIPS 203), hybridized with X25519 | ML-KEM mandated for key establishment |
| **ECDSA** | Signature | High | **ML-DSA** (FIPS 204); **SLH-DSA** (FIPS 205) as conservative backup | ML-DSA mandated for signatures |
| **DSA** | Signature | High | **ML-DSA** (FIPS 204) or **SLH-DSA** (FIPS 205) | ML-DSA mandated for signatures |
| **MD5** | Hash | High | **SHA-384 / SHA-512** | SHA-384+ mandated |
| **SHA-1** | Hash | Medium | **SHA-384 / SHA-512** | SHA-384+ mandated |
| **3DES** | Symmetric | Medium | **AES-256-GCM** | AES-256 mandated |
| **X.509 cert / private key** | Certificate | High | Inventory + reissue with **ML-DSA** once PKI supports FIPS 204 | ML-DSA mandated for PKI/code-signing |

> Symmetric crypto and hashing are only *weakened* by quantum attacks (Grover's algorithm halves the effective security level), not broken. AES-256 retains ~128-bit post-quantum security, which is why CNSA 2.0 keeps AES-256 and SHA-384.

The full machine-readable mapping lives in [`src/pqc_migrator/rules/default_rules.json`](src/pqc_migrator/rules/default_rules.json).

---

## Architecture

```
src/pqc_migrator/
├── models.py            # Immutable Finding / ScanResult / Severity / CryptoCategory
├── rules/
│   ├── model.py         # Rule + RulePattern data model (validated)
│   ├── engine.py        # Loads rules-as-data; applies regex rules per language
│   └── default_rules.json   # The source-of-truth mapping table
├── scanners/
│   ├── python_ast.py    # Precise Python scanner (ast module, call-signature matching)
│   ├── text.py          # Regex scanner for JS/TS/Go/Java/config/cert
│   └── walker.py        # Filesystem walk + extension→language dispatch
├── output/
│   ├── table.py         # rich human table
│   ├── json_out.py      # JSON
│   ├── sarif.py         # SARIF 2.1.0
│   └── cbom.py          # Crypto Bill of Materials (JSON + Markdown)
├── tls_scan.py          # Live TLS handshake classifier
├── cryptoagility.py     # Hybrid X25519 + ML-KEM-768 handshake (liboqs + fallback)
└── cli.py               # typer CLI (scan / tls / cbom / demo)
```

**Design choices worth calling out:**

- **Rules are data, not code.** Detection metadata and remediation guidance live in JSON. The same rule pack drives the AST scanner, the regex scanner, the SARIF rule descriptors, and the README mapping table — one source of truth.
- **AST for Python, regex for the rest.** The Python scanner resolves call targets structurally, eliminating the comment/string false positives that plague pure-regex scanners. Other languages use a language-scoped regex engine.
- **Immutable models.** Findings are frozen dataclasses, safely passed between scanner, engine, and renderers.
- **No home-grown crypto.** The hybrid demo uses audited `liboqs` for ML-KEM-768 and `cryptography` for X25519/HKDF. If `liboqs` is absent, the PQC half degrades to a clearly-labeled illustrative placeholder that warns loudly — it never silently pretends to be post-quantum secure.

---

## CI / SARIF integration

`scan --sarif` emits a valid SARIF 2.1.0 document that GitHub code scanning ingests directly. Add this to a workflow to surface PQC findings in the Security tab:

```yaml
- name: PQC scan
  run: pqc-migrator scan . --sarif -o pqc.sarif --no-fail-on-findings
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pqc.sarif
```

This repository's own CI runs ruff, mypy, and pytest across Python 3.11/3.12, plus CodeQL and a security scan (bandit + pip-audit + gitleaks). See [`.github/workflows/`](.github/workflows/).

---

## Roadmap

- [ ] Certificate deep-parsing (signature OID + key type) using `cryptography` instead of the sparse stdlib peer-cert dict.
- [ ] CycloneDX CBOM export for SBOM-tool interoperability.
- [ ] More languages: C/C++, C#, Rust, PHP.
- [ ] Confidence scoring and inline suppression comments (`# pqc-migrator: ignore`).
- [ ] Pre-commit hook and GitHub Action distribution.
- [ ] Detection of key *sizes* (e.g. RSA-2048 vs RSA-4096) for finer prioritization.

---

## References

- [NIST: First 3 Finalized Post-Quantum Encryption Standards (Aug 2024)](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
- [FIPS 203 — ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Standard)](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Standard)](https://csrc.nist.gov/pubs/fips/205/final)
- [NSA CNSA 2.0 suite and migration timeline](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [draft-ietf-tls-ecdhe-mlkem — Hybrid ECDHE-MLKEM for TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [Open Quantum Safe — liboqs / liboqs-python](https://openquantumsafe.org/)
- [SARIF 2.1.0 specification (OASIS)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

---

## License

[MIT](LICENSE) © 2026 Basit Sherazi
