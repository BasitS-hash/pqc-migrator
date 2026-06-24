"""Crypto Bill of Materials (CBOM) generation.

Summarizes all detected cryptography usage into a structured inventory:
which primitives appear, how often, where, and their quantum-readiness
status. Emitted as JSON (machine-readable) and Markdown (human/report).
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from pqc_migrator.models import ScanResult

_GENERATOR = "pqc-migrator"
_CBOM_SPEC = "pqc-migrator-cbom/1.0"


def build_cbom(
    result: ScanResult, *, generator_version: str = "0.0.0"
) -> dict[str, Any]:
    """Build a CBOM dictionary from a scan result."""
    by_primitive: dict[str, dict[str, Any]] = {}
    locations_by_primitive: dict[str, list[str]] = defaultdict(list)

    for finding in result.sorted_findings():
        entry = by_primitive.setdefault(
            finding.primitive,
            {
                "primitive": finding.primitive,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "rule_ids": set(),
                "recommendation": finding.recommendation,
                "cnsa_note": finding.cnsa_note,
                "quantum_status": "vulnerable",
                "occurrences": 0,
            },
        )
        entry["occurrences"] += 1
        entry["rule_ids"].add(finding.rule_id)
        locations_by_primitive[finding.primitive].append(
            f"{finding.file_path}:{finding.line}"
        )

    components = []
    for name in sorted(by_primitive):
        entry = by_primitive[name]
        components.append(
            {
                "primitive": entry["primitive"],
                "category": entry["category"],
                "severity": entry["severity"],
                "quantum_status": entry["quantum_status"],
                "occurrences": entry["occurrences"],
                "rule_ids": sorted(entry["rule_ids"]),
                "recommended_replacement": entry["recommendation"],
                "cnsa_note": entry["cnsa_note"],
                "locations": locations_by_primitive[name],
            }
        )

    return {
        "bomFormat": _CBOM_SPEC,
        "generator": {"name": _GENERATOR, "version": generator_version},
        "generatedAt": datetime.now(UTC).isoformat(),
        "metadata": {
            "root": result.root,
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "total_findings": len(result.findings),
        },
        "summary": result.counts_by_severity(),
        "components": components,
    }


def render_cbom_json(cbom: dict[str, Any]) -> str:
    return json.dumps(cbom, indent=2)


def render_cbom_markdown(cbom: dict[str, Any]) -> str:
    """Render a CBOM dictionary as a Markdown report."""
    meta = cbom["metadata"]
    lines: list[str] = []
    lines.append("# Cryptography Bill of Materials (CBOM)")
    lines.append("")
    lines.append(f"- **Scanned root:** `{meta['root']}`")
    lines.append(f"- **Generated at:** {cbom['generatedAt']}")
    lines.append(
        f"- **Files scanned:** {meta['files_scanned']} "
        f"({meta['files_skipped']} skipped)"
    )
    lines.append(f"- **Total findings:** {meta['total_findings']}")
    lines.append("")

    lines.append("## Severity summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for severity, count in cbom["summary"].items():
        if count:
            lines.append(f"| {severity} | {count} |")
    lines.append("")

    lines.append("## Cryptographic components")
    lines.append("")
    if not cbom["components"]:
        lines.append("_No quantum-vulnerable cryptography detected._")
        return "\n".join(lines) + "\n"

    lines.append(
        "| Primitive | Category | Severity | Status | Occurrences "
        "| Recommended replacement |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for comp in cbom["components"]:
        lines.append(
            f"| {comp['primitive']} | {comp['category']} | {comp['severity']} "
            f"| {comp['quantum_status']} | {comp['occurrences']} "
            f"| {comp['recommended_replacement']} |"
        )
    lines.append("")

    lines.append("## CNSA 2.0 notes")
    lines.append("")
    for comp in cbom["components"]:
        if comp["cnsa_note"]:
            lines.append(f"- **{comp['primitive']}**: {comp['cnsa_note']}")
    lines.append("")

    return "\n".join(lines) + "\n"
