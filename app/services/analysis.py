"""Service orchestration for analysis ingestion and execution."""

from __future__ import annotations

from datetime import datetime, timezone
import base64
import binascii
import json
import time
from hashlib import sha256
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

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

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
        agent_public_keys: dict[str, str] | None = None,
    ) -> None:
        self._store = store
        self._detection = detection_service
        self._governance = governance_service
        self._analytics = analytics_service
        self._github_resolver = github_resolver
        self._agent_public_keys = {k.lower(): v for k, v in (agent_public_keys or {}).items()}
        self._verify_key_cache: dict[str, VerifyKey] = {}

    def ingest_analysis(
        self,
        request: AnalysisIngestionRequest,
        background_tasks: BackgroundTasks | None = None,
    ) -> AnalysisRecord:
        analysis_id = new_analysis_id()
        timestamp = _now()
        provenance_inputs = request.provenance_data.model_dump()

        github_summary_added = False
        if self._github_resolver and request.pr_number:
            metadata = self._github_resolver.collect_pr_metadata(
                repo_full_name=request.repo,
                pr_number=int(request.pr_number),
                head_sha=request.head_sha,
            )
            if metadata:
                provenance_inputs["github_metadata"] = metadata
                summary = metadata.get("review_summary")
                if summary:
                    provenance_inputs["github_review_stats"] = summary
                    github_summary_added = True

        if self._github_resolver and request.pr_number and not github_summary_added:
            github_stats = self._github_resolver.review_stats(
                repo_full_name=request.repo,
                pr_number=int(request.pr_number),
            )
            if github_stats:
                provenance_inputs["github_review_stats"] = github_stats

        record = AnalysisRecord(
            analysis_id=analysis_id,
            status=AnalysisStatus.RECEIVED,
            repo_id=request.repo,
            pr_number=request.pr_number,
            base_sha=request.base_sha,
            head_sha=request.head_sha,
            created_at=timestamp,
            updated_at=timestamp,
            provenance_inputs=provenance_inputs,
        )
        self._store.create_analysis(record)
        lines = [
            self._map_changed_line(analysis_id, request, payload) for payload in request.provenance_data.changed_lines
        ]
        if lines:
            self._store.add_changed_lines(analysis_id, lines)
            avg_conf = self._average_confidence(lines)
            if avg_conf is not None:
                record.provenance_inputs["provenance_confidence"] = avg_conf
                self._store.update_analysis(record)
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
        resolved_via_resolver = False
        if not attribution.agent.agent_id:
            agent_id, session_id, evidence = self._resolve_agent(
                repo=request.repo,
                pr_number=request.pr_number,
                commit_sha=attribution.commit_sha,
            )
            if agent_id:
                attribution.agent.agent_id = agent_id
            if session_id:
                attribution.agent_session_id = session_id
            if evidence:
                attribution.provenance_marker = json.dumps(evidence)
            resolved_via_resolver = True

        content_sha = payload.content_sha256
        if payload.content:
            computed_sha = self._hash_content(payload.content)
            if content_sha and content_sha.lower() != computed_sha:
                raise ValueError("Provided content_sha256 does not match content")
            content_sha = computed_sha
        if payload.attestation_signature and not content_sha:
            raise ValueError("attestation_signature provided without content SHA")

        confidence = self._derive_confidence(
            agent_id=attribution.agent.agent_id,
            content_sha=content_sha,
            signature=payload.attestation_signature,
            resolved_via_resolver=resolved_via_resolver,
        )
        if confidence is not None:
            attribution.confidence_score = confidence

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
            content_sha256=content_sha,
            attestation_signature=payload.attestation_signature,
            attribution=attribution,
        )

    def _resolve_agent(
        self,
        *,
        repo: str,
        pr_number: str,
        commit_sha: str | None,
    ) -> tuple[str | None, str | None, dict]:
        if not self._github_resolver:
            return None, None, {}
        return self._github_resolver.resolve_agent(repo, pr_number, commit_sha)

    @staticmethod
    def _hash_content(content: str) -> str:
        return sha256(content.encode("utf-8")).hexdigest()

    def _derive_confidence(
        self,
        *,
        agent_id: str,
        content_sha: str | None,
        signature: str | None,
        resolved_via_resolver: bool,
    ) -> float | None:
        agent_key_known = self._has_public_key(agent_id)
        if signature and content_sha:
            success, reason = self._verify_attestation(agent_id, content_sha, signature)
            if success:
                return 1.0
            if reason == "missing_key":
                return 0.4
            return 0.0
        if signature and not content_sha:
            return 0.0
        if agent_key_known and not signature:
            return 0.2
        if agent_id:
            return 0.6 if resolved_via_resolver else 0.5
        return 0.0

    def _has_public_key(self, agent_id: str | None) -> bool:
        if not agent_id:
            return False
        return agent_id.lower() in self._agent_public_keys

    def _verify_attestation(self, agent_id: str | None, content_sha: str, signature: str) -> tuple[bool, str | None]:
        if not agent_id:
            return False, "missing_agent"
        key_str = self._agent_public_keys.get(agent_id.lower())
        if not key_str:
            return False, "missing_key"
        try:
            verify_key = self._verify_key_cache.get(agent_id.lower())
            if not verify_key:
                verify_key = VerifyKey(base64.b64decode(key_str))
                self._verify_key_cache[agent_id.lower()] = verify_key
            verify_key.verify(content_sha.encode("utf-8"), base64.b64decode(signature))
            return True, None
        except (BadSignatureError, ValueError, binascii.Error):
            return False, "invalid_signature"

    @staticmethod
    def _average_confidence(lines: list[ChangedLine]) -> float | None:
        scores = [line.attribution.confidence_score for line in lines if line.attribution.confidence_score is not None]
        if not scores:
            return None
        return sum(scores) / len(scores)

    def list_findings(self, analysis_id: str) -> list[Finding]:
        return self._store.list_findings(analysis_id)

    def get_analysis(self, analysis_id: str) -> AnalysisRecord | None:
        return self._store.get_analysis(analysis_id)
