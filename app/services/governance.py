"""Governance service for policy decisions."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

import base64
import binascii
import json
from hashlib import sha256

from nacl.signing import SigningKey

import base64
import binascii
import json
from hashlib import sha256

from nacl.signing import SigningKey

from app.core.config import settings
from app.core.identifiers import new_decision_id
from app.telemetry import EventSink, NullEventSink
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

    def __init__(self, sink: EventSink | None = None) -> None:
        self._sink = sink or NullEventSink()
        self._signing_key: SigningKey | None = None
        if settings.decision_signing_key:
            try:
                key_bytes = base64.b64decode(settings.decision_signing_key)
                self._signing_key = SigningKey(key_bytes)
            except (binascii.Error, ValueError):  # type: ignore[name-defined]
                self._signing_key = None

    def evaluate(
        self,
        record: AnalysisRecord,
        lines: list[ChangedLine],
        findings: list[Finding],
    ) -> tuple[PolicyDecision, dict]:
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

        metadata = record.provenance_inputs.get("github_metadata", {}) if isinstance(record.provenance_inputs, dict) else {}
        review_summary = metadata.get("review_summary") or {}
        commit_summary = metadata.get("commit_summary") or {}

        bot_override_count = review_summary.get("bot_block_overrides", 0)
        bot_block_resolved = review_summary.get("bot_block_resolved", 0)
        force_push_after_approval = commit_summary.get("force_push_after_approval") is True or review_summary.get("force_push_after_approval_count", 0) > 0

        if bot_override_count:
            outcome = PolicyOutcome.BLOCK if settings.provenance_block_on_unknown else PolicyOutcome.WARN
            rationale = (
                f"Detected {bot_override_count} bot review(s) requesting changes that were bypassed by merge"
            )
            if bot_block_resolved:
                rationale += f" ({bot_block_resolved} subsequently resolved)"

        elif force_push_after_approval and outcome != PolicyOutcome.BLOCK:
            outcome = PolicyOutcome.WARN
            rationale = "Force-push occurred after approval; requires manual verification."

        if bot_override_count or force_push_after_approval:
            evidence_links.append("provenance:github_review")
            risk_summary["bot_block_overrides"] = bot_override_count
            risk_summary["bot_block_resolved"] = bot_block_resolved
            risk_summary["force_push_after_approval"] = bool(force_push_after_approval)
            self._emit_review_alert(
                record=record,
                review_summary=review_summary,
                commit_summary=commit_summary,
                overrides=bot_override_count,
                resolved=bot_block_resolved,
                force_push=bool(force_push_after_approval),
            )

        decision = PolicyDecision(
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
        bundle = self._build_decision_bundle(
            record=record,
            lines=lines,
            findings=findings,
            decision=decision,
        )
        self._emit_decision_event(record.analysis_id, bundle)
        return decision, bundle

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

    def _emit_review_alert(
        self,
        *,
        record: AnalysisRecord,
        review_summary: dict,
        commit_summary: dict,
        overrides: int,
        resolved: int,
        force_push: bool,
    ) -> None:
        event = {
            "event_type": "review_override_alert",
            "analysis_id": record.analysis_id,
            "repo_id": record.repo_id,
            "pr_number": record.pr_number,
            "overrides": overrides,
            "resolved": resolved,
            "force_push_after_approval": force_push,
            "override_details": review_summary.get("bot_block_override_details", []),
            "merge_actor": commit_summary.get("last_merge_actor"),
            "merged_at": commit_summary.get("last_merge_at"),
            "timestamp": _now().isoformat(),
        }
        try:
            self._sink.publish(event)
        except Exception:  # pragma: no cover - telemetry should not break decision flow
            pass

    def _build_decision_bundle(
        self,
        *,
        record: AnalysisRecord,
        lines: list[ChangedLine],
        findings: list[Finding],
        decision: PolicyDecision,
    ) -> dict:
        payload_body = {
            "analysis_id": record.analysis_id,
            "repo_id": record.repo_id,
            "pr_number": record.pr_number,
            "decided_at": decision.decided_at.isoformat(),
            "outcome": decision.outcome.value,
            "policy_version": decision.policy_version,
            "rationale": decision.rationale,
            "risk_summary": decision.risk_summary,
            "provenance_confidence": record.provenance_inputs.get("provenance_confidence"),
            "thresholds": {
                "warn": settings.policy_warn_thresholds,
                "block": settings.policy_block_thresholds,
            },
            "detector_capabilities": record.provenance_inputs.get("detector_capabilities"),
            "line_count": len(lines),
            "finding_count": len(findings),
            "inputs_sha256": sha256(
                json.dumps(record.provenance_inputs, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
        }
        canonical = json.dumps(payload_body, sort_keys=True, separators=(",", ":"))
        payload_bytes = canonical.encode("utf-8")
        payload_b64 = base64.b64encode(payload_bytes).decode()
        sha_digest = sha256(payload_bytes).hexdigest()
        envelope = {
            "payloadType": "application/provenance.decision+json",
            "payload": payload_b64,
            "payloadSha256": sha_digest,
            "signatures": [],
        }
        if self._signing_key is not None:
            signature = self._signing_key.sign(payload_bytes).signature
            envelope["signatures"].append(
                {
                    "keyid": settings.decision_key_id or "decision-key",
                    "sig": base64.b64encode(signature).decode(),
                }
            )
        return envelope

    def _emit_decision_event(self, analysis_id: str, bundle: dict) -> None:
        try:
            self._sink.publish(
                {
                    "event_type": "decision_bundle",
                    "analysis_id": analysis_id,
                    "payload": bundle,
                    "timestamp": _now().isoformat(),
                }
            )
        except Exception:  # pragma: no cover
            pass
