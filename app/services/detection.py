"""Detection pipeline for security and quality findings."""

from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from app.core.identifiers import new_finding_id
from app.models.domain import (
    AnalysisRecord,
    ChangedLine,
    Finding,
    FindingStatus,
    SeverityLevel,
    ChangeType,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class DetectionService:
    """Executes configured detectors against changed lines."""

    def __init__(self, detectors: Iterable["BaseDetector"] | None = None) -> None:
        self._detectors = list(detectors or [SemgrepDetector()])

    def run(self, record: AnalysisRecord, lines: list[ChangedLine]) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self._detectors:
            findings.extend(detector.execute(record, lines))
        return findings


class BaseDetector:
    """Base contract for detectors."""

    name = "base"
    default_severity = SeverityLevel.MEDIUM
    rule_key = "BASE000"
    category = "general"

    def execute(self, record: AnalysisRecord, lines: list[ChangedLine]) -> list[Finding]:
        raise NotImplementedError

    def _build_finding(
        self,
        record: AnalysisRecord,
        line: ChangedLine,
        message: str,
        severity: SeverityLevel | None = None,
        rule_version: str = "1.0.0",
    ) -> Finding:
        return Finding(
            finding_id=new_finding_id(),
            analysis_id=record.analysis_id,
            repo_id=record.repo_id,
            pr_number=record.pr_number,
            file_path=line.file_path,
            line_number=line.line_number,
            rule_key=self.rule_key,
            rule_version=rule_version,
            category=self.category,
            severity=severity or self.default_severity,
            engine_name=self.name,
            message=message,
            detected_at=_now(),
            status=FindingStatus.OPEN,
            attribution=line.attribution,
        )


class SemgrepDetector(BaseDetector):
    name = "semgrep"
    rule_key = "semgrep"
    category = "general"

    CONFIG_PATH = Path(__file__).resolve().parent.parent / "detection_rules" / "semgrep_rules.yml"
    CATEGORY_MAP = {
        "sql-injection-concat": "sqli",
        "dangerous-eval": "code_execution",
    }
    SEVERITY_MAP = {
        "ERROR": SeverityLevel.HIGH,
        "WARNING": SeverityLevel.MEDIUM,
        "INFO": SeverityLevel.LOW,
    }

    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path) if config_path else self.CONFIG_PATH

    def execute(self, record: AnalysisRecord, lines: list[ChangedLine]) -> list[Finding]:
        filtered_lines = [line for line in lines if line.change_type != ChangeType.DELETED]
        if not filtered_lines:
            return []

        line_map: dict[tuple[str, int], ChangedLine] = {}
        with TemporaryWorkspace(filtered_lines) as workspace:
            line_map = workspace.line_map
            cmd = [
                "semgrep",
                "--json",
                "--quiet",
                "--config",
                str(self.config_path),
                str(workspace.root),
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            except FileNotFoundError as exc:  # pragma: no cover - environment dependency
                raise RuntimeError(
                    "Semgrep executable not found. Ensure semgrep is installed in the runtime environment."
                ) from exc
            if result.returncode not in (0, 1):
                raise RuntimeError(f"Semgrep failed: {result.stderr.strip()}")
            payload = json.loads(result.stdout or "{}")

        findings: list[Finding] = []
        for match in payload.get("results", []):
            rel_path = match.get("path")
            start = match.get("start", {})
            line_number = start.get("line")
            if not rel_path or not line_number:
                continue
            key = (rel_path, line_number)
            changed_line = line_map.get(key)
            if not changed_line:
                continue
            severity = self.SEVERITY_MAP.get(match.get("extra", {}).get("severity", "").upper(), SeverityLevel.LOW)
            message = match.get("extra", {}).get("message") or match.get("extra", {}).get("metadata", {}).get(
                "message", ""
            )
            findings.append(
                Finding(
                    finding_id=new_finding_id(),
                    analysis_id=record.analysis_id,
                    repo_id=record.repo_id,
                    pr_number=record.pr_number,
                    file_path=changed_line.file_path,
                    line_number=changed_line.line_number,
                    rule_key=match.get("check_id", self.rule_key),
                    rule_version=match.get("extra", {}).get("metadata", {}).get("version", "1.0.0"),
                    category=self.CATEGORY_MAP.get(match.get("check_id"), self.category),
                    severity=severity,
                    engine_name=self.name,
                    message=message or "Semgrep finding",
                    detected_at=_now(),
                    status=FindingStatus.OPEN,
                    attribution=changed_line.attribution,
                )
            )
        return findings


class TemporaryWorkspace:
    """Writes changed lines to temporary files for Semgrep execution."""

    def __init__(self, lines: list[ChangedLine]) -> None:
        self.lines = lines
        self._tempdir = None
        self.line_map: dict[tuple[str, int], ChangedLine] = {}

    def __enter__(self):
        import tempfile

        self._tempdir = Path(tempfile.mkdtemp(prefix="semgrep-lines-"))
        per_file: dict[str, list[ChangedLine]] = defaultdict(list)
        for line in self.lines:
            per_file[line.file_path].append(line)
        for file_path, entries in per_file.items():
            entries.sort(key=lambda line: line.line_number)
            rel_path = Path(file_path)
            temp_path = self._tempdir / rel_path
            temp_path.parent.mkdir(parents=True, exist_ok=True)
            buffer: list[str] = []
            for idx, changed_line in enumerate(entries, start=1):
                buffer.append(changed_line.content or "")
                self.line_map[(rel_path.as_posix(), idx)] = changed_line
            temp_path.write_text("\n".join(buffer) + "\n", encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import shutil

        if self._tempdir and self._tempdir.exists():
            shutil.rmtree(self._tempdir)
        self._tempdir = None

    @property
    def root(self) -> Path:
        if not self._tempdir:
            raise RuntimeError("Workspace not initialised")
        return self._tempdir
