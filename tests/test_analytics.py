from datetime import datetime, timezone

import fakeredis

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


def test_risk_rate_aggregation_by_agent():
    now = datetime.now(timezone.utc)
    analysis_id = "an_demo"
    agent = AgentIdentity(agent_id="claude-3-opus")

    store = RedisWarehouse(fakeredis.FakeRedis(decode_responses=True))
    analytics = AnalyticsService(store)

    record = AnalysisRecord(
        analysis_id=analysis_id,
        status=AnalysisStatus.COMPLETED,
        repo_id="acme/shop",
        pr_number="101",
        base_sha="abc",
        head_sha="def",
        created_at=now,
        updated_at=now,
        provenance_inputs={},
    )
    store.create_analysis(record)

    line1 = ChangedLine(
        analysis_id=analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        head_sha=record.head_sha,
        file_path="services/orders.py",
        line_number=30,
        change_type=ChangeType.ADDED,
        timestamp=now,
        branch="feature/analytics",
        language="python",
        content="query = build_query(user_input)",
        attribution=ProvenanceAttribution(agent=agent),
    )
    line2 = ChangedLine(
        analysis_id=analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        head_sha=record.head_sha,
        file_path="services/orders.py",
        line_number=31,
        change_type=ChangeType.ADDED,
        timestamp=now,
        branch="feature/analytics",
        language="python",
        content="execute(query)",
        attribution=ProvenanceAttribution(agent=agent),
    )
    store.add_changed_lines(analysis_id, [line1, line2])

    finding = Finding(
        finding_id="fd_demo",
        analysis_id=analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        file_path=line1.file_path,
        line_number=line1.line_number,
        rule_key="sql-injection-concat",
        rule_version="1.0.0",
        category="sqli",
        severity=SeverityLevel.HIGH,
        engine_name="semgrep",
        message="demo finding",
        detected_at=now,
        status=FindingStatus.OPEN,
        attribution=line1.attribution,
    )
    store.add_findings(analysis_id, [finding])

    series = analytics.query_series(time_window="1d", metric="risk_rate", group_by="agent_id")

    assert series.metric == "risk_rate"
    assert len(series.data) == 1
    point = series.data[0]
    assert point.agent_id == agent.agent_id
    assert point.numerator == 1
    assert point.denominator == 2
    assert point.value == 500.0  # 1 finding per 2 lines → 500 per 1000 lines
