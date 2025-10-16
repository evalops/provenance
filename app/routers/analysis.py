"""API routes for analysis ingestion and status."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from app.core.config import settings
from app.dependencies import get_analysis_service, get_store
from app.repositories.redis_store import RedisWarehouse
from app.schemas.analysis import (
    AnalysisIngestionRequest,
    AnalysisIngestionResponse,
    AnalysisStatusResponse,
)
from app.services.analysis import AnalysisService


router = APIRouter(prefix=f"{settings.api_v1_prefix}/analysis", tags=["analysis"])


@router.post("", response_model=AnalysisIngestionResponse, status_code=status.HTTP_202_ACCEPTED)
def submit_analysis(
    payload: AnalysisIngestionRequest,
    background_tasks: BackgroundTasks,
    analysis_service: AnalysisService = Depends(get_analysis_service),
) -> AnalysisIngestionResponse:
    record = analysis_service.ingest_analysis(payload, background_tasks=background_tasks)
    return AnalysisIngestionResponse(
        analysis_id=record.analysis_id,
        status=record.status,
        status_url=f"{settings.service_base_url}{settings.api_v1_prefix}/analysis/{record.analysis_id}",
    )


@router.get("/{analysis_id}", response_model=AnalysisStatusResponse)
def get_analysis_status(
    analysis_id: str,
    analysis_service: AnalysisService = Depends(get_analysis_service),
    store: RedisWarehouse = Depends(get_store),
) -> AnalysisStatusResponse:
    record = analysis_service.get_analysis(analysis_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    findings_total = len(store.list_findings(analysis_id))
    decision = store.get_policy_decision(analysis_id)
    risk_summary = decision.risk_summary if decision else {}
    return AnalysisStatusResponse(
        analysis_id=record.analysis_id,
        status=record.status,
        updated_at=record.updated_at,
        findings_total=findings_total,
        risk_summary=risk_summary,
    )
