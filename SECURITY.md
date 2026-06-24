# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in pqc-migrator, please report it
**privately** so it can be fixed before public disclosure.

- Use GitHub's [private vulnerability reporting](https://github.com/BasitS-hash/pqc-migrator/security/advisories/new)
  ("Report a vulnerability" under the Security tab).
- Please do **not** open a public issue for security problems.

Include, where possible:

- A description of the vulnerability and its impact.
- Steps to reproduce or a proof of concept.
- The affected version or commit.

You can expect an acknowledgement within a few business days and a coordinated
disclosure timeline once the issue is triaged.

## Scope and threat model

pqc-migrator is a **static analysis and inventory tool**. It reads source code,
configuration, and certificate files, and it can open outbound TLS connections
for the `tls` command. Relevant security considerations:

- **Untrusted input.** The scanner parses arbitrary repository content. File
  reads are size-capped and decoded with `errors="replace"`; Python parsing
  uses the standard-library `ast` module (no `eval`/`exec`). Report any input
  that causes a crash, hang, or unexpected file access.
- **Outbound connections.** `pqc-migrator tls <host:port>` initiates a TLS
  handshake to a user-supplied endpoint. It performs standard certificate
  verification and never sends credentials.
- **No home-grown cryptography.** The hybrid handshake demo uses the audited
  `liboqs` library for ML-KEM-768 and `cryptography` for X25519/HKDF. When
  `liboqs` is unavailable, the demo falls back to an **illustrative,
  non-post-quantum** placeholder and emits an explicit `RuntimeWarning`. This
  fallback is for demonstration only and must never be relied on for real
  protection.

## Important note on findings

A clean pqc-migrator scan is **necessary but not sufficient** for
quantum-readiness. The tool detects common patterns; it cannot prove the
absence of vulnerable cryptography (e.g. crypto invoked via reflection, dynamic
imports, vendored binaries, or unsupported languages). Treat findings as a
prioritized starting point for migration, not a compliance guarantee.

## Supported versions

This project is pre-1.0. Security fixes are applied to the latest released
version and `main`.
