"""API schemas for governance and policy decisions."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.domain import PolicyOutcome


class GovernanceDecisionResponse(BaseModel):
    """Response body for GET /v1/analysis/{analysis_id}/decision."""

    analysis_id: str
    decision: PolicyOutcome
    rationale: str
    decided_at: datetime
    evidence_links: list[str] = Field(default_factory=list)
    risk_summary: dict = Field(default_factory=dict)
    provenance_status: str
    policy_version: str
