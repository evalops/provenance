from datetime import datetime, timezone
import sys
import types

from app.models.domain import (
    AnalysisRecord,
    AnalysisStatus,
    AgentIdentity,
    ChangeType,
    ChangedLine,
    ProvenanceAttribution,
    SeverityLevel,
)
from app.services.detection import DetectionService, BaseDetector
from app.core.config import Settings


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


def test_detection_service_loads_external_detectors(monkeypatch):
    settings = Settings(detector_module_paths=["custom.detector"])
    monkeypatch.setattr("app.services.detection.settings", settings)

    class ExternalDetector(BaseDetector):
        name = "external"
        rule_key = "ext001"
        category = "external"
        default_severity = SeverityLevel.LOW

        def execute(self, record, lines):
            if not lines:
                return []
            return [
                self._build_finding(record, lines[0], "external finding", severity=SeverityLevel.LOW)
            ]

    module = types.ModuleType("custom.detector")

    def register_detectors():
        return [ExternalDetector()]

    module.register_detectors = register_detectors
    monkeypatch.setitem(sys.modules, "custom.detector", module)

    detection = DetectionService(detectors=[])
    now = datetime.now(timezone.utc)
    record = AnalysisRecord(
        analysis_id="an_ext",
        status=AnalysisStatus.IN_PROGRESS,
        repo_id="acme",
        pr_number="1",
        base_sha="base",
        head_sha="head",
        created_at=now,
        updated_at=now,
        provenance_inputs={}
    )
    line = ChangedLine(
        analysis_id=record.analysis_id,
        repo_id=record.repo_id,
        pr_number=record.pr_number,
        head_sha=record.head_sha,
        file_path="svc.py",
        line_number=1,
        change_type=ChangeType.ADDED,
        timestamp=now,
        branch="feature",
        language="python",
        content="value = 1",
        attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="hook")),
    )

    findings = detection.run(record, [line])
    assert any(f.engine_name == "external" for f in findings)
