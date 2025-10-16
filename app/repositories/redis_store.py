"""Redis-backed persistence layer for analysis data."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from redis import Redis

from app.models.domain import (
    AnalysisRecord,
    AnalysisStatus,
    ChangedLine,
    Finding,
    PolicyDecision,
)


def _timestamp(dt: datetime) -> float:
    return dt.timestamp()


class RedisWarehouse:
    """Stores analyses, findings, and decisions in Redis."""

    def __init__(self, client: Redis) -> None:
        self._client = client

    def create_analysis(self, record: AnalysisRecord) -> None:
        self._client.set(self._analysis_key(record.analysis_id), record.model_dump_json())
        self._client.zadd("analysis:index", {record.analysis_id: _timestamp(record.created_at)})

    def get_analysis(self, analysis_id: str) -> Optional[AnalysisRecord]:
        data = self._client.get(self._analysis_key(analysis_id))
        if not data:
            return None
        return AnalysisRecord.model_validate_json(data)

    def update_analysis(self, analysis: AnalysisRecord) -> None:
        self._client.set(self._analysis_key(analysis.analysis_id), analysis.model_dump_json())
        self._client.zadd("analysis:index", {analysis.analysis_id: _timestamp(analysis.created_at)})

    def list_analyses(self) -> list[AnalysisRecord]:
        ids = self._client.zrange("analysis:index", 0, -1)
        if not ids:
            return []
        pipeline = self._client.pipeline()
        for analysis_id in ids:
            pipeline.get(self._analysis_key(analysis_id))
        raw_records = pipeline.execute()
        analyses: list[AnalysisRecord] = []
        for blob in raw_records:
            if blob:
                analyses.append(AnalysisRecord.model_validate_json(blob))
        return analyses

    def add_changed_lines(self, analysis_id: str, lines: Iterable[ChangedLine]) -> None:
        key = self._lines_key(analysis_id)
        if not lines:
            return
        payload = [line.model_dump_json() for line in lines]
        self._client.rpush(key, *payload)

    def get_changed_lines(self, analysis_id: str) -> list[ChangedLine]:
        key = self._lines_key(analysis_id)
        entries = self._client.lrange(key, 0, -1)
        return [ChangedLine.model_validate_json(entry) for entry in entries]

    def add_findings(self, analysis_id: str, findings: Iterable[Finding]) -> None:
        key = self._findings_key(analysis_id)
        mapping = {finding.finding_id: finding.model_dump_json() for finding in findings}
        if mapping:
            self._client.hset(key, mapping=mapping)

    def list_findings(self, analysis_id: str) -> list[Finding]:
        key = self._findings_key(analysis_id)
        values = self._client.hvals(key)
        return [Finding.model_validate_json(value) for value in values]

    def upsert_policy_decision(self, decision: PolicyDecision) -> None:
        key = self._decision_key(decision.analysis_id)
        self._client.set(key, decision.model_dump_json())

    def get_policy_decision(self, analysis_id: str) -> Optional[PolicyDecision]:
        key = self._decision_key(analysis_id)
        data = self._client.get(key)
        if not data:
            return None
        return PolicyDecision.model_validate_json(data)

    def update_analysis_status(
        self,
        analysis_id: str,
        status: AnalysisStatus,
        error_message: Optional[str] = None,
    ) -> None:
        record = self.get_analysis(analysis_id)
        if not record:
            return
        record.status = status
        record.error_message = error_message
        record.updated_at = datetime.now(timezone.utc)
        self.update_analysis(record)

    @staticmethod
    def _analysis_key(analysis_id: str) -> str:
        return f"analysis:{analysis_id}"

    @staticmethod
    def _lines_key(analysis_id: str) -> str:
        return f"analysis:{analysis_id}:lines"

    @staticmethod
    def _findings_key(analysis_id: str) -> str:
        return f"analysis:{analysis_id}:findings"

    @staticmethod
    def _decision_key(analysis_id: str) -> str:
        return f"analysis:{analysis_id}:decision"
