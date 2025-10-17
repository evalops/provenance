"""API schemas for analysis ingestion and status tracking."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.models.domain import ChangeType, AnalysisStatus


class AttributionPayload(BaseModel):
    """Client provided provenance metadata for a changed line."""

    agent_id: str
    agent_version: Optional[str] = None
    agent_session_id: Optional[str] = None
    commit_sha: Optional[str] = None
    provenance_marker: Optional[str] = Field(
        None,
        description="Raw provenance marker string to support traceability checks.",
    )


class ChangedLinePayload(BaseModel):
    """Client provided representation of a changed line in a diff."""

    file_path: str
    line_number: int
    change_type: ChangeType
    content: Optional[str] = None
    language: Optional[str] = None
    author_identity: Optional[str] = None
    timestamp: Optional[datetime] = None
    attribution: AttributionPayload
    content_sha256: Optional[str] = Field(
        None, description="Optional hex-encoded SHA256 of the line content supplied by the client."
    )
    attestation_signature: Optional[str] = Field(
        None,
        description="Optional base64-encoded Ed25519 signature over the content SHA256 from the agent runtime.",
    )


class ProvenanceDataPayload(BaseModel):
    """Structured payload of changed lines and supporting provenance inputs."""

    changed_lines: list[ChangedLinePayload] = Field(
        default_factory=list,
        description="Denominator facts for the analysis run.",
    )
    metadata: dict = Field(
        default_factory=dict,
        description="Opaque dictionary for any provenance signals (trailers, attestations, etc.).",
    )


class AnalysisIngestionRequest(BaseModel):
    """Request body for POST /v1/analysis."""

    repo: str = Field(..., description="Repository identifier in {org}/{repo} form.")
    pr_number: str
    base_sha: str
    head_sha: str
    branch: Optional[str] = None
    provenance_data: ProvenanceDataPayload = Field(default_factory=ProvenanceDataPayload)


class AnalysisIngestionResponse(BaseModel):
    """Response body acknowledging analysis ingestion."""

    analysis_id: str
    status: AnalysisStatus
    status_url: str


class AnalysisStatusResponse(BaseModel):
    """Response body for polling analysis status."""

    analysis_id: str
    status: AnalysisStatus
    updated_at: datetime
    findings_total: int
    risk_summary: dict = Field(default_factory=dict)


class DecisionBundleResponse(BaseModel):
    """Response payload for /v1/analysis/{id}/bundle."""

    analysis_id: str
    bundle: dict
    request_id: str
