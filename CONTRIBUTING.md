# Contributing to pqc-migrator

Thanks for your interest in improving pqc-migrator. Contributions of all
kinds are welcome — new detection rules, additional languages, bug fixes,
and documentation.

## Development setup

```bash
git clone https://github.com/BasitS-hash/pqc-migrator.git
cd pqc-migrator
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Local quality gate

Before opening a PR, run the same checks CI runs:

```bash
ruff check src tests          # lint
ruff format --check src tests # formatting
mypy                          # type check
pytest --cov=pqc_migrator --cov-report=term-missing   # tests + coverage
bandit -r src -c pyproject.toml                        # security lint
```

All must pass. Test coverage should stay at or above **85%** on the rule
engine and scanners.

## Adding a detection rule

Detection rules are **data**, not code. To add coverage:

1. Add a rule object to
   [`src/pqc_migrator/rules/default_rules.json`](src/pqc_migrator/rules/default_rules.json)
   with a new `PQCxxx` id, `primitive`, `category`, `severity`, `message`,
   `recommendation`, `cnsa_note`, and one or more `patterns` (each with a
   `regex` and the `languages` it applies to).
2. For **Python** precision, add a structural call signature to
   `_CALL_SIGNATURES` in
   [`src/pqc_migrator/scanners/python_ast.py`](src/pqc_migrator/scanners/python_ast.py)
   rather than relying on regex (the Python scanner does not run regex rules).
3. Add a fixture under `tests/fixtures/` and assert the new finding in the
   appropriate test module.

Keep severities honest: **key establishment** (RSA/ECDH/DH) is `critical`
because of Harvest-Now-Decrypt-Later; signatures are `high`; weakened
hashes/symmetric ciphers are `medium`/`high` per CNSA 2.0.

## Coding standards

- Python 3.11+, fully type-annotated (`mypy --strict` clean).
- Immutable data models (frozen dataclasses) where practical.
- Small, focused modules. No `print` debugging in library code.
- No hardcoded secrets; validate input at boundaries.
- **Never** hand-roll cryptographic primitives. Use audited libraries.

## Commit and PR conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `ci:`.
- Keep PRs focused and include a short description and test plan.
- CI (lint, type check, tests, security scan) must be green before review.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
