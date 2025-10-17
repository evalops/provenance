from datetime import datetime, timezone

import pytest

from app.models.domain import (
    AnalysisRecord,
    AnalysisStatus,
    AgentIdentity,
    ChangeType,
    ChangedLine,
    Finding,
    FindingStatus,
    ProvenanceAttribution,
    SeverityLevel,
)
from app.services.governance import GovernanceService
from app.core.config import Settings


def _baseline_record() -> AnalysisRecord:
    now = datetime.now(timezone.utc)
    return AnalysisRecord(
        analysis_id="an-governance",
        status=AnalysisStatus.COMPLETED,
        repo_id="acme/repo",
        pr_number="1",
        base_sha="base",
        head_sha="head",
        created_at=now,
        updated_at=now,
        provenance_inputs={},
    )


def test_high_severity_triggers_warn(monkeypatch):
    settings = Settings()
    monkeypatch.setattr("app.services.governance.settings", settings)
    service = GovernanceService()
    record = _baseline_record()
    line = ChangedLine(
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        head_sha=record.head_sha,
        file_path="svc.py",
        line_number=10,
        change_type=ChangeType.ADDED,
        timestamp=record.created_at,
        branch="feature",
        language="python",
        content="result = sanitize(user_input)",
        attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="github-copilot")),
    )
    finding = Finding(
        finding_id="fd-warn",
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        file_path=line.file_path,
        line_number=line.line_number,
        rule_key="code-risk",
        rule_version="1.0.0",
        category="code_execution",
        severity=SeverityLevel.HIGH,
        engine_name="semgrep",
        message="hazard",
        detected_at=record.created_at,
        status=FindingStatus.OPEN,
        attribution=line.attribution,
    )

    decision = service.evaluate(record, [line], [finding])
    assert decision.outcome.value == "warn"


def test_critical_triggers_block(monkeypatch):
    settings = Settings()
    monkeypatch.setattr("app.services.governance.settings", settings)
    service = GovernanceService()
    record = _baseline_record()
    line = ChangedLine(
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        head_sha=record.head_sha,
        file_path="svc.py",
        line_number=10,
        change_type=ChangeType.ADDED,
        timestamp=record.created_at,
        branch="feature",
        language="python",
        content="result = sanitize(user_input)",
        attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="claude-3")),
    )
    finding = Finding(
        finding_id="fd-block",
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        file_path=line.file_path,
        line_number=line.line_number,
        rule_key="critical-risk",
        rule_version="1.0.0",
        category="sqli",
        severity=SeverityLevel.CRITICAL,
        engine_name="semgrep",
        message="critical",
        detected_at=record.created_at,
        status=FindingStatus.OPEN,
        attribution=line.attribution,
    )

    decision = service.evaluate(record, [line], [finding])
    assert decision.outcome.value == "block"


def test_unknown_provenance_blocks_when_enabled(monkeypatch):
    settings = Settings(provenance_block_on_unknown=True)
    monkeypatch.setattr("app.services.governance.settings", settings)
    service = GovernanceService()
    record = _baseline_record()
    line = ChangedLine(
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        head_sha=record.head_sha,
        file_path="svc.py",
        line_number=10,
        change_type=ChangeType.ADDED,
        timestamp=record.created_at,
        branch="feature",
        language="python",
        content="result = sanitize(user_input)",
        attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="")),
    )

    decision = service.evaluate(record, [line], [])
    assert decision.outcome.value == "block"


def test_category_thresholds_override(monkeypatch):
    settings = Settings(
        policy_warn_thresholds={"code_execution": 1},
        policy_block_thresholds={"code_execution": 2},
    )
    monkeypatch.setattr("app.services.governance.settings", settings)
    service = GovernanceService()
    record = _baseline_record()
    line = ChangedLine(
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        head_sha=record.head_sha,
        file_path="svc.py",
        line_number=10,
        change_type=ChangeType.ADDED,
        timestamp=record.created_at,
        branch="feature",
        language="python",
        content="result = sanitize(user_input)",
        attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="claude")),
    )
    findings = [
        Finding(
            finding_id=f"fd-{idx}",
            analysis_id=record.analysis_id,
            repo_id=record.repo_id,
            pr_number=record.pr_number,
            file_path=line.file_path,
            line_number=line.line_number,
            rule_key="threshold",
            rule_version="1.0.0",
            category="code_execution",
            severity=SeverityLevel.MEDIUM,
            engine_name="semgrep",
            message="",
            detected_at=record.created_at,
            status=FindingStatus.OPEN,
            attribution=line.attribution,
        )
        for idx in range(2)
    ]

    decision = service.evaluate(record, [line], findings[:1])
    assert decision.outcome.value == "warn"

    decision_block = service.evaluate(record, [line], findings)
    assert decision_block.outcome.value == "block"


def test_bot_override_triggers_warn(monkeypatch):
    settings = Settings()
    monkeypatch.setattr("app.services.governance.settings", settings)
    service = GovernanceService()
    record = _baseline_record()
    record.provenance_inputs = {
        "github_metadata": {
            "review_summary": {
                "bot_block_overrides": 2,
                "bot_block_resolved": 1,
            },
            "commit_summary": {
                "force_push_after_approval": False,
            },
        }
    }

    decision = service.evaluate(record, [], [])
    assert decision.outcome.value == "warn"
    assert decision.risk_summary["bot_block_overrides"] == 2
    assert decision.risk_summary["bot_block_resolved"] == 1


def test_bot_override_blocks_when_policy_enabled(monkeypatch):
    settings = Settings(provenance_block_on_unknown=True)
    monkeypatch.setattr("app.services.governance.settings", settings)
    service = GovernanceService()
    record = _baseline_record()
    record.provenance_inputs = {
        "github_metadata": {
            "review_summary": {
                "bot_block_overrides": 1,
            },
            "commit_summary": {
                "force_push_after_approval": True,
            },
        }
    }

    decision = service.evaluate(record, [], [])
    assert decision.outcome.value == "block"
    assert decision.risk_summary["force_push_after_approval"] is True
