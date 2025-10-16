from datetime import datetime, timezone

from app.models.domain import (
    AnalysisRecord,
    AnalysisStatus,
    AgentIdentity,
    ChangeType,
    ChangedLine,
    ProvenanceAttribution,
    SeverityLevel,
)
from app.services.detection import DetectionService


def test_semgrep_detector_flags_sql_concat():
    now = datetime.now(timezone.utc)
    record = AnalysisRecord(
        analysis_id="an_test",
        status=AnalysisStatus.IN_PROGRESS,
        repo_id="acme/shop",
        pr_number="42",
        base_sha="base",
        head_sha="head",
        created_at=now,
        updated_at=now,
        provenance_inputs={},
    )
    changed_line = ChangedLine(
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        head_sha=record.head_sha,
        file_path="services/orders.py",
        line_number=12,
        change_type=ChangeType.ADDED,
        timestamp=now,
        branch="feature/test",
        author_identity="dev",
        language="python",
        content="result = eval(user_input)",
        attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="claude-3-opus")),
    )

    detection = DetectionService()
    findings = detection.run(record, [changed_line])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_key == "dangerous-eval"
    assert finding.category == "code_execution"
    assert finding.severity == SeverityLevel.MEDIUM
    assert finding.file_path == changed_line.file_path
    assert finding.line_number == changed_line.line_number
