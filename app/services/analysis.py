"""Service orchestration for analysis ingestion and execution."""

from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import TYPE_CHECKING

from fastapi import BackgroundTasks

from app.core.identifiers import new_analysis_id
from app.models.domain import (
    AnalysisRecord,
    AnalysisStatus,
    ChangedLine,
    ProvenanceAttribution,
    AgentIdentity,
    Finding,
)
from app.repositories.redis_store import RedisWarehouse
from app.schemas.analysis import AnalysisIngestionRequest, ChangedLinePayload
from app.services.analytics import AnalyticsService
from app.services.detection import DetectionService
from app.services.governance import GovernanceService
from app.telemetry import increment_analysis_ingestion, record_analysis_duration, record_analysis_findings

if TYPE_CHECKING:
    from app.provenance.github_resolver import GitHubProvenanceResolver


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AnalysisService:
    """Coordinates ingestion, detection, analytics, and governance workflows."""

    def __init__(
        self,
        store: RedisWarehouse,
        detection_service: DetectionService,
        governance_service: GovernanceService,
        analytics_service: AnalyticsService,
        github_resolver: "GitHubProvenanceResolver | None" = None,
    ) -> None:
        self._store = store
        self._detection = detection_service
        self._governance = governance_service
        self._analytics = analytics_service
        self._github_resolver = github_resolver

    def ingest_analysis(
        self,
        request: AnalysisIngestionRequest,
        background_tasks: BackgroundTasks | None = None,
    ) -> AnalysisRecord:
        analysis_id = new_analysis_id()
        timestamp = _now()
        record = AnalysisRecord(
            analysis_id=analysis_id,
            status=AnalysisStatus.RECEIVED,
            repo_id=request.repo,
            pr_number=request.pr_number,
            base_sha=request.base_sha,
            head_sha=request.head_sha,
            created_at=timestamp,
            updated_at=timestamp,
            provenance_inputs=request.provenance_data.model_dump(),
        )
        self._store.create_analysis(record)
        lines = [
            self._map_changed_line(analysis_id, request, payload) for payload in request.provenance_data.changed_lines
        ]
        if lines:
            self._store.add_changed_lines(analysis_id, lines)
        record.status = AnalysisStatus.IN_PROGRESS
        record.updated_at = _now()
        self._store.update_analysis(record)
        if background_tasks is not None:
            background_tasks.add_task(self.execute_analysis, analysis_id)
        else:
            self.execute_analysis(analysis_id)
        increment_analysis_ingestion()
        return record

    def execute_analysis(self, analysis_id: str) -> None:
        record = self._store.get_analysis(analysis_id)
        if not record:
            return
        try:
            started = time.perf_counter()
            record.status = AnalysisStatus.IN_PROGRESS
            record.updated_at = _now()
            self._store.update_analysis(record)

            lines = self._store.get_changed_lines(analysis_id)
            findings = self._detection.run(record, lines)
            if findings:
                self._store.add_findings(analysis_id, findings)

            self._analytics.index_analysis(record, lines, findings)
            decision = self._governance.evaluate(record, lines, findings)
            self._store.upsert_policy_decision(decision)

            record.status = AnalysisStatus.COMPLETED
            record.updated_at = _now()
            self._store.update_analysis(record)
            duration = time.perf_counter() - started
            record_analysis_duration(duration)
            record_analysis_findings(len(findings))
        except Exception as exc:  # pragma: no cover - defensive catch for background jobs
            record.status = AnalysisStatus.FAILED
            record.updated_at = _now()
            record.error_message = str(exc)
            self._store.update_analysis(record)

    def _map_changed_line(
        self,
        analysis_id: str,
        request: AnalysisIngestionRequest,
        payload: ChangedLinePayload,
    ) -> ChangedLine:
        timestamp = payload.timestamp or _now()
        attribution = ProvenanceAttribution(
            agent=AgentIdentity(
                agent_id=payload.attribution.agent_id,
                agent_version=payload.attribution.agent_version,
            ),
            agent_session_id=payload.attribution.agent_session_id,
            commit_sha=payload.attribution.commit_sha,
            provenance_marker=payload.attribution.provenance_marker,
        )
        if not attribution.agent.agent_id:
            agent_id, session_id = self._resolve_agent(
                repo=request.repo,
                pr_number=request.pr_number,
                commit_sha=attribution.commit_sha,
            )
            if agent_id:
                attribution.agent.agent_id = agent_id
            if session_id:
                attribution.agent_session_id = session_id
        return ChangedLine(
            analysis_id=analysis_id,
            repo_id=request.repo,
            pr_number=request.pr_number,
            head_sha=request.head_sha,
            file_path=payload.file_path,
            line_number=payload.line_number,
            change_type=payload.change_type,
            timestamp=timestamp,
            branch=request.branch,
            author_identity=payload.author_identity,
            language=payload.language,
            content=payload.content,
            attribution=attribution,
        )

    def _resolve_agent(
        self,
        *,
        repo: str,
        pr_number: str,
        commit_sha: str | None,
    ) -> tuple[str | None, str | None]:
        if not self._github_resolver:
            return None, None
        return self._github_resolver.resolve_agent(repo, pr_number, commit_sha)

    def list_findings(self, analysis_id: str) -> list[Finding]:
        return self._store.list_findings(analysis_id)

    def get_analysis(self, analysis_id: str) -> AnalysisRecord | None:
        return self._store.get_analysis(analysis_id)
