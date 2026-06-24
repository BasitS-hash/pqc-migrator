"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqc_migrator.rules.engine import RuleEngine
from pqc_migrator.scanners.walker import CodebaseScanner


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def engine() -> RuleEngine:
    return RuleEngine.with_defaults()


@pytest.fixture
def scanner(engine: RuleEngine) -> CodebaseScanner:
    return CodebaseScanner(engine)
