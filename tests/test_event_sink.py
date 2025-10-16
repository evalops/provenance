from datetime import datetime, timezone
from pathlib import Path
import json

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
from app.telemetry import FileEventSink


def test_file_event_sink_writes_analysis_metrics(tmp_path: Path):
    sink_path = tmp_path / "events.jsonl"
    sink = FileEventSink(sink_path)
    store = RedisWarehouse(fakeredis.FakeRedis(decode_responses=True))
    analytics = AnalyticsService(store, sink=sink)

    now = datetime.now(timezone.utc)
    record = AnalysisRecord(
        analysis_id="an-sink",
        status=AnalysisStatus.COMPLETED,
        repo_id="acme/api",
        pr_number="55",
        base_sha="abc",
        head_sha="def",
        created_at=now,
        updated_at=now,
        provenance_inputs={}
    )

    line = ChangedLine(
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        head_sha=record.head_sha,
        file_path="handlers.py",
        line_number=10,
        change_type=ChangeType.ADDED,
        timestamp=now,
        branch="feature/sink",
        language="python",
        content="result = eval(user_input)",
        attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="github-copilot")),
    )
    finding = Finding(
        finding_id="fd-sink",
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        file_path=line.file_path,
        line_number=line.line_number,
        rule_key="dangerous-eval",
        rule_version="1.0.0",
        category="code_execution",
        severity=SeverityLevel.MEDIUM,
        engine_name="semgrep",
        message="eval usage",
        detected_at=now,
        status=FindingStatus.OPEN,
        attribution=line.attribution,
    )

    analytics.index_analysis(record, [line], [finding])

    payloads = sink_path.read_text(encoding="utf-8").strip().splitlines()
    assert payloads
    event = json.loads(payloads[0])
    assert event["analysis_id"] == record.analysis_id
    assert event["total_lines"] == 1
    assert event["total_findings"] == 1
    metrics = event["agent_metrics"][0]
    assert metrics["agent_id"] == "github-copilot"
    assert metrics["findings_by_category"] == {"code_execution": 1}
