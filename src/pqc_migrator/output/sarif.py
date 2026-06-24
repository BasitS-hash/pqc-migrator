"""SARIF 2.1.0 renderer.

Produces a Static Analysis Results Interchange Format document that GitHub
code scanning can ingest. Rules are emitted once in ``tool.driver.rules`` and
referenced by index from each result, per the SARIF spec.
"""

from __future__ import annotations

import json
from typing import Any

from pqc_migrator.models import ScanResult
from pqc_migrator.rules.engine import RuleEngine

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "pqc-migrator"
TOOL_URI = "https://github.com/BasitS-hash/pqc-migrator"


def _rule_descriptors(
    engine: RuleEngine,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    descriptors: list[dict[str, Any]] = []
    index_by_id: dict[str, int] = {}
    for idx, rule in enumerate(engine.rules):
        index_by_id[rule.rule_id] = idx
        descriptors.append(
            {
                "id": rule.rule_id,
                "name": rule.primitive.replace(" ", ""),
                "shortDescription": {"text": f"{rule.primitive} is quantum-vulnerable"},
                "fullDescription": {"text": rule.message},
                "help": {"text": f"{rule.recommendation} {rule.cnsa_note}".strip()},
                "defaultConfiguration": {"level": rule.severity.sarif_level},
                "properties": {
                    "category": rule.category.value,
                    "severity": rule.severity.value,
                    "tags": ["cryptography", "post-quantum", rule.category.value],
                },
            }
        )
    return descriptors, index_by_id


def render_sarif(
    result: ScanResult, engine: RuleEngine, *, version: str = "0.0.0"
) -> str:
    """Render a scan result as a SARIF 2.1.0 JSON document."""
    descriptors, index_by_id = _rule_descriptors(engine)

    sarif_results: list[dict[str, Any]] = []
    for finding in result.sorted_findings():
        rule_index = index_by_id.get(finding.rule_id, -1)
        entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": finding.severity.sarif_level,
            "message": {"text": f"{finding.message} {finding.recommendation}".strip()},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {
                            "startLine": max(finding.line, 1),
                            "startColumn": max(finding.column, 1),
                        },
                    }
                }
            ],
            "properties": {
                "primitive": finding.primitive,
                "category": finding.category.value,
                "cnsa_note": finding.cnsa_note,
                "detector": finding.detector,
            },
        }
        if rule_index >= 0:
            entry["ruleIndex"] = rule_index
        sarif_results.append(entry)

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "version": version,
                        "rules": descriptors,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(document, indent=2)
