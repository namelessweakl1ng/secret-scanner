"""SARIF v2.1.0 reporter for CI integration (GitHub Code Scanning, Azure DevOps)."""

from __future__ import annotations

import json

from .base import Reporter


class SARIFReporter(Reporter):
    """Render scan results as SARIF 2.1.0 JSON."""

    def render(self, result) -> str:  # noqa: ANN001
        rules: list[dict] = []
        rule_index: dict[str, int] = {}
        for f in result.findings:
            if f.rule_id not in rule_index:
                rule_index[f.rule_id] = len(rules)
                rules.append(
                    {
                        "id": f.rule_id,
                        "name": f.rule_name,
                        "shortDescription": {"text": f.rule_name},
                        "fullDescription": {"text": f"Provider: {f.provider}"},
                        "defaultConfiguration": {"level": _sarif_level(f.severity)},
                        "properties": {
                            "provider": f.provider,
                            "tags": ["security", "secret"],
                        },
                    }
                )

        sarif = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "secret-scanner",
                            "version": result.scanner_version,
                            "informationUri": "https://github.com/secret-scanner/secret-scanner",
                            "rules": rules,
                        }
                    },
                    "results": [
                        {
                            **f.to_sarif(),
                            "ruleIndex": rule_index[f.rule_id],
                        }
                        for f in result.findings
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)


def _sarif_level(severity) -> str:  # noqa: ANN001
    if severity.name == "CRITICAL":
        return "error"
    if severity.name == "HIGH":
        return "error"
    if severity.name == "MEDIUM":
        return "warning"
    if severity.name == "LOW":
        return "note"
    return "none"


__all__ = ["SARIFReporter"]
