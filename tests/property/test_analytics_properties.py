from datetime import datetime, timezone

import fakeredis
from hypothesis import given, strategies as st

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


@st.composite
def agent_stats(draw):
    agent_ids = draw(
        st.lists(
            st.text(min_size=1, max_size=5),
            min_size=1,
            max_size=4,
            unique=True,
        )
    )
    stats = []
    for agent_id in agent_ids:
        line_count = draw(st.integers(min_value=1, max_value=6))
        finding_count = draw(st.integers(min_value=0, max_value=line_count))
        stats.append((agent_id, line_count, finding_count))
    return stats


@given(agent_stats())
def test_risk_rate_matches_counts(stats):
    store = RedisWarehouse(fakeredis.FakeRedis(decode_responses=True))
    analytics = AnalyticsService(store)

    now = datetime.now(timezone.utc)
    record = AnalysisRecord(
        analysis_id="an-property",
        status=AnalysisStatus.COMPLETED,
        repo_id="acme/property",
        pr_number="1",
        base_sha="base",
        head_sha="head",
        created_at=now,
        updated_at=now,
        provenance_inputs={},
    )
    store.create_analysis(record)

    line_counter = 1
    for agent_id, line_count, finding_count in stats:
        agent_identity = AgentIdentity(agent_id=agent_id)
        lines = []
        for _ in range(line_count):
            change_type = draw_change_type(line_counter)
            lines.append(
                ChangedLine(
                    analysis_id=record.analysis_id,
                    repo_id=record.repo_id,
                    pr_number=record.pr_number,
                    head_sha=record.head_sha,
                    file_path=f"svc/{agent_id}.py",
                    line_number=line_counter,
                    change_type=change_type,
                    timestamp=now,
                    branch="feature/property",
                    language="python",
                    content=f"value = {line_counter}",
                    attribution=ProvenanceAttribution(agent=agent_identity),
                )
            )
            line_counter += 1
        store.add_changed_lines(record.analysis_id, lines)

        findings = []
        for idx in range(finding_count):
            target_line = lines[idx]
            findings.append(
                Finding(
                    finding_id=f"fd-{agent_id}-{idx}",
                    analysis_id=record.analysis_id,
                    repo_id=record.repo_id,
                    pr_number=record.pr_number,
                    file_path=target_line.file_path,
                    line_number=target_line.line_number,
                    rule_key="prop",
                    rule_version="1.0.0",
                    category="property",
                    severity=SeverityLevel.MEDIUM,
                    engine_name="test",
                    message="generated",
                    detected_at=now,
                    status=FindingStatus.OPEN,
                    attribution=target_line.attribution,
                )
            )
        if findings:
            store.add_findings(record.analysis_id, findings)

    series = analytics.query_series(time_window="1d", metric="risk_rate", group_by="agent_id")
    for agent_id, line_count, finding_count in stats:
        point = next(p for p in series.data if p.agent_id == agent_id)
        expected_rate = (finding_count / line_count) * 1000 if line_count else 0.0
        assert point.denominator == line_count
        assert point.numerator == finding_count
        assert point.value == expected_rate


def draw_change_type(seed: int) -> ChangeType:
    # Deterministic but varied change types based on line number
    return [ChangeType.ADDED, ChangeType.MODIFIED, ChangeType.DELETED][seed % 3]
