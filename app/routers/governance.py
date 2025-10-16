"""API routes for governance decisions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import settings
from app.dependencies import get_store
from app.repositories.redis_store import RedisWarehouse
from app.schemas.governance import GovernanceDecisionResponse


router = APIRouter(prefix=f"{settings.api_v1_prefix}/analysis", tags=["governance"])


@router.get("/{analysis_id}/decision", response_model=GovernanceDecisionResponse)
def get_policy_decision(
    analysis_id: str,
    store: RedisWarehouse = Depends(get_store),
) -> GovernanceDecisionResponse:
    decision = store.get_policy_decision(analysis_id)
    if not decision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not available")
    return GovernanceDecisionResponse(
        analysis_id=decision.analysis_id,
        decision=decision.outcome,
        rationale=decision.rationale,
        decided_at=decision.decided_at,
        evidence_links=decision.evidence_links,
        risk_summary=decision.risk_summary,
        provenance_status=decision.provenance_status,
        policy_version=decision.policy_version,
    )
