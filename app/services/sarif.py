"""Utilities for generating SARIF reports from findings."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from app.models.domain import AnalysisRecord, Finding, SeverityLevel

_SEVERITY_MAP = {
    SeverityLevel.CRITICAL: "error",
    SeverityLevel.HIGH: "error",
    SeverityLevel.MEDIUM: "warning",
    SeverityLevel.LOW: "note",
}


def build_sarif(analysis: AnalysisRecord, findings: Iterable[Finding]) -> dict:
    results = []
    for finding in findings:
        level = _SEVERITY_MAP.get(finding.severity, "warning")
        results.append(
            {
                "ruleId": finding.rule_key,
                "level": level,
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {
                                "startLine": finding.line_number,
                            },
                        }
                    }
                ],
                "properties": {
                    "analysis_id": analysis.analysis_id,
                    "repo_id": analysis.repo_id,
                    "pr_number": analysis.pr_number,
                    "engine_name": finding.engine_name,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Provenance Governance",
                        "informationUri": "https://github.com/evalops/provenance",
                        "rules": [],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": analysis.created_at.isoformat(),
                        "endTimeUtc": analysis.updated_at.isoformat(),
                    }
                ],
                "results": results,
            }
        ],
    }
    return sarif
