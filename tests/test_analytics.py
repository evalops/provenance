from datetime import datetime, timedelta, timezone

import fakeredis
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
from app.repositories.redis_store import RedisWarehouse
from app.services.analytics import AnalyticsService


def _bootstrap_store() -> AnalyticsService:
    now = datetime.now(timezone.utc) - timedelta(hours=12)
    store = RedisWarehouse(fakeredis.FakeRedis(decode_responses=True))
    analytics = AnalyticsService(store)

    # Analysis 1 - agent claude-3-opus
    record1 = AnalysisRecord(
        analysis_id="an-1",
        status=AnalysisStatus.COMPLETED,
        repo_id="acme/shop",
        pr_number="101",
        base_sha="abc",
        head_sha="def",
        created_at=now,
        updated_at=now,
        provenance_inputs={},
    )
    store.create_analysis(record1)
    claude = AgentIdentity(agent_id="claude-3-opus")
    lines_agent1 = [
        ChangedLine(
            analysis_id=record1.analysis_id,
            repo_id=record1.repo_id,
            pr_number=record1.pr_number,
            head_sha=record1.head_sha,
            file_path="services/orders.py",
            line_number=30 + idx,
            change_type=change_type,
            timestamp=now,
            branch="feature/analytics",
            language="python",
            content=content,
            attribution=ProvenanceAttribution(agent=claude),
        )
        for idx, (change_type, content) in enumerate(
            [
                (ChangeType.ADDED, "query = build_query(user_input)"),
                (ChangeType.MODIFIED, "query = sanitize(user_input)"),
                (ChangeType.DELETED, "dangerous_call()"),
            ]
        )
    ]
    store.add_changed_lines(record1.analysis_id, lines_agent1)
    finding1 = Finding(
        finding_id="fd-1",
        analysis_id=record1.analysis_id,
        repo_id=record1.repo_id,
        pr_number=record1.pr_number,
        file_path=lines_agent1[0].file_path,
        line_number=lines_agent1[0].line_number,
        rule_key="sql-injection-concat",
        rule_version="1.0.0",
        category="sqli",
        severity=SeverityLevel.HIGH,
        engine_name="semgrep",
        message="risk",
        detected_at=now,
        status=FindingStatus.OPEN,
        attribution=lines_agent1[0].attribution,
    )
    store.add_findings(record1.analysis_id, [finding1])

    # Analysis 2 - agent github-copilot
    record2_time = now + timedelta(hours=2)
    record2 = AnalysisRecord(
        analysis_id="an-2",
        status=AnalysisStatus.COMPLETED,
        repo_id="acme/shop",
        pr_number="102",
        base_sha="ghi",
        head_sha="jkl",
        created_at=record2_time,
        updated_at=record2_time,
        provenance_inputs={},
    )
    store.create_analysis(record2)
    copilot = AgentIdentity(agent_id="github-copilot")
    lines_agent2 = [
        ChangedLine(
            analysis_id=record2.analysis_id,
            repo_id=record2.repo_id,
            pr_number=record2.pr_number,
            head_sha=record2.head_sha,
            file_path="web/forms.ts",
            line_number=90 + idx,
            change_type=ChangeType.ADDED,
            timestamp=record2_time,
            branch="feature/forms",
            language="typescript",
            content=content,
            attribution=ProvenanceAttribution(agent=copilot),
        )
        for idx, content in enumerate(
            [
                "const payload = { email, password };",
                "submit(payload);",
                "return true;",
            ]
        )
    ]
    store.add_changed_lines(record2.analysis_id, lines_agent2)
    findings_agent2 = [
        Finding(
            finding_id="fd-2",
            analysis_id=record2.analysis_id,
            repo_id=record2.repo_id,
            pr_number=record2.pr_number,
            file_path=lines_agent2[1].file_path,
            line_number=lines_agent2[1].line_number,
            rule_key="dangerous-eval",
            rule_version="1.0.0",
            category="code_execution",
            severity=SeverityLevel.MEDIUM,
            engine_name="semgrep",
            message="eval usage",
            detected_at=record2_time,
            status=FindingStatus.OPEN,
            attribution=lines_agent2[1].attribution,
        ),
        Finding(
            finding_id="fd-3",
            analysis_id=record2.analysis_id,
            repo_id=record2.repo_id,
            pr_number=record2.pr_number,
            file_path=lines_agent2[2].file_path,
            line_number=lines_agent2[2].line_number,
            rule_key="dangerous-eval",
            rule_version="1.0.0",
            category="code_execution",
            severity=SeverityLevel.MEDIUM,
            engine_name="semgrep",
            message="eval usage again",
            detected_at=record2_time,
            status=FindingStatus.OPEN,
            attribution=lines_agent2[2].attribution,
        ),
    ]
    store.add_findings(record2.analysis_id, findings_agent2)
    return analytics


def test_risk_rate_aggregation_by_agent():
    analytics = _bootstrap_store()
    series = analytics.query_series(time_window="1d", metric="risk_rate", group_by="agent_id")

    assert series.metric == "risk_rate"
    assert len(series.data) == 2
    claude = next(point for point in series.data if point.agent_id == "claude-3-opus")
    copilot = next(point for point in series.data if point.agent_id == "github-copilot")
    assert claude.numerator == 1
    assert claude.denominator == 3
    assert claude.value == pytest.approx(333.333, rel=1e-3)
    assert copilot.numerator == 2
    assert copilot.denominator == 3
    assert copilot.value == pytest.approx(666.666, rel=1e-3)


def test_volume_churn_and_complexity_metrics():
    analytics = _bootstrap_store()
    volume_series = analytics.query_series(time_window="1d", metric="code_volume", group_by="agent_id")
    churn_series = analytics.query_series(time_window="1d", metric="code_churn_rate", group_by="agent_id")
    complexity_series = analytics.query_series(time_window="1d", metric="avg_line_complexity", group_by="agent_id")

    claude_volume = next(point for point in volume_series.data if point.agent_id == "claude-3-opus")
    assert claude_volume.value == 3.0
    assert claude_volume.unit == "lines"

    claude_churn = next(point for point in churn_series.data if point.agent_id == "claude-3-opus")
    assert claude_churn.numerator == 2  # modified + deleted
    assert claude_churn.denominator == 3
    assert claude_churn.unit == "percent"
    assert claude_churn.value == pytest.approx(66.666, rel=1e-3)

    copilot_complexity = next(point for point in complexity_series.data if point.agent_id == "github-copilot")
    assert copilot_complexity.unit == "avg_non_whitespace_chars"
    assert copilot_complexity.value > 0


def test_agent_behavior_report_highlights_top_categories():
    analytics = _bootstrap_store()
    report = analytics.agent_behavior_report(time_window="1d", top_categories=2)

    assert report.snapshots
    claude_snapshot = next(s for s in report.snapshots if s.agent_id == "claude-3-opus")
    assert claude_snapshot.code_volume == 3
    assert claude_snapshot.churn_lines == 2
    assert claude_snapshot.churn_rate == pytest.approx(2 / 3, rel=1e-6)
    assert claude_snapshot.top_vulnerability_categories == {"sqli": 1}

    copilot_snapshot = next(s for s in report.snapshots if s.agent_id == "github-copilot")
    assert copilot_snapshot.top_vulnerability_categories == {"code_execution": 2}
    assert copilot_snapshot.avg_line_complexity > 0
