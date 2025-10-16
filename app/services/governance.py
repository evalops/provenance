"""Governance service for policy decisions."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from app.core.config import settings
from app.core.identifiers import new_decision_id
from app.models.domain import (
    AnalysisRecord,
    ChangedLine,
    Finding,
    PolicyDecision,
    PolicyOutcome,
    SeverityLevel,
)


def _now():
    return datetime.now(timezone.utc)


class GovernanceService:
    """Evaluates policy decisions based on findings and provenance coverage."""

    def evaluate(
        self,
        record: AnalysisRecord,
        lines: list[ChangedLine],
        findings: list[Finding],
    ) -> PolicyDecision:
        coverage = self._calculate_provenance_coverage(lines)
        findings_summary = self._summarise_findings(findings)

        outcome = PolicyOutcome.ALLOW
        rationale = "All policies satisfied."
        evidence_links: list[str] = []

        if settings.provenance_block_on_unknown and coverage["unknown_line_count"] > 0:
            outcome = PolicyOutcome.BLOCK
            rationale = "Unknown agents detected; provenance coverage policy enforced."

        high_severity = findings_summary["findings_by_severity"].get(SeverityLevel.HIGH.value, 0)
        critical_severity = findings_summary["findings_by_severity"].get(SeverityLevel.CRITICAL.value, 0)
        if critical_severity > 0:
            outcome = PolicyOutcome.BLOCK
            rationale = "Critical findings detected."
        elif high_severity >= settings.risk_high_severity_threshold:
            outcome = PolicyOutcome.WARN
            rationale = "High severity findings exceed configured threshold."

        for category, count in findings_summary["findings_by_category"].items():
            block_threshold = settings.policy_block_thresholds.get(category)
            warn_threshold = settings.policy_warn_thresholds.get(category)
            if block_threshold and count >= block_threshold:
                outcome = PolicyOutcome.BLOCK
                rationale = f"{category} findings exceeded block threshold ({count} >= {block_threshold})."
                break
            if (
                warn_threshold
                and count >= warn_threshold
                and outcome != PolicyOutcome.BLOCK
            ):
                outcome = PolicyOutcome.WARN
                rationale = f"{category} findings exceeded warn threshold ({count} >= {warn_threshold})."

        risk_summary = {
            "findings_total": findings_summary["total_findings"],
            "findings_by_category": findings_summary["findings_by_category"],
            "findings_by_severity": findings_summary["findings_by_severity"],
            "coverage": coverage,
        }

        return PolicyDecision(
            decision_id=new_decision_id(),
            analysis_id=record.analysis_id,
            repo_id=record.repo_id,
            pr_number=record.pr_number,
            decided_at=_now(),
            outcome=outcome,
            rationale=rationale,
            risk_summary=risk_summary,
            provenance_status=f"{coverage['coverage_percent']:.2f}% lines attributed",
            policy_version=settings.default_policy_version,
            evidence_links=evidence_links,
        )

    @staticmethod
    def _calculate_provenance_coverage(lines: list[ChangedLine]) -> dict:
        total_lines = len(lines)
        attributed_lines = sum(1 for line in lines if line.attribution.agent.agent_id)
        unknown_lines = total_lines - attributed_lines
        coverage_percent = (attributed_lines / total_lines * 100) if total_lines else 100.0
        return {
            "total_lines": total_lines,
            "attributed_lines": attributed_lines,
            "unknown_line_count": unknown_lines,
            "coverage_percent": coverage_percent,
        }

    @staticmethod
    def _summarise_findings(findings: list[Finding]) -> dict:
        by_category = Counter(finding.category for finding in findings)
        by_severity = Counter(finding.severity.value for finding in findings)
        return {
            "total_findings": len(findings),
            "findings_by_category": dict(by_category),
            "findings_by_severity": dict(by_severity),
        }
