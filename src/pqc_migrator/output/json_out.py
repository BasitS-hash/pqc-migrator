"""JSON output renderer."""

from __future__ import annotations

import json

from pqc_migrator.models import ScanResult


def render_json(result: ScanResult, *, indent: int = 2) -> str:
    """Render a scan result as a deterministic JSON document."""
    return json.dumps(result.to_dict(), indent=indent, sort_keys=False)
