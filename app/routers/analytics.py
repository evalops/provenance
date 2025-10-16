"""API routes for analytics reporting."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.config import settings
from app.dependencies import get_analytics_service
from app.schemas.analytics import AnalyticsSummaryResponse, AgentBehaviorResponse
from app.services.analytics import AnalyticsService


router = APIRouter(prefix=f"{settings.api_v1_prefix}/analytics", tags=["analytics"])


@router.get("/summary", response_model=AnalyticsSummaryResponse)
def get_analytics_summary(
    time_window: str = Query(..., description="Duration string such as 7d or 24h."),
    metric: str = Query(
        ...,
        description="Metric identifier (risk_rate, provenance_coverage, code_volume, code_churn_rate, avg_line_complexity).",
    ),
    group_by: str = Query("agent_id", description="Grouping dimension."),
    category: str | None = Query(None, description="Optional filter for finding category."),
    agent_id: str | None = Query(None, description="Optional filter for agent id."),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> AnalyticsSummaryResponse:
    try:
        series = analytics_service.query_series(
            time_window=time_window,
            metric=metric,
            group_by=group_by,
            category=category,
            agent_id=agent_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    return AnalyticsSummaryResponse(result=series, request_id=f"rq_{uuid.uuid4().hex}")


@router.get("/agents/behavior", response_model=AgentBehaviorResponse)
def get_agent_behavior_summary(
    time_window: str = Query(..., description="Duration string such as 7d or 24h."),
    agent_id: str | None = Query(None, description="Optional filter for a specific agent id."),
    top_categories: int = Query(
        3, ge=1, le=10, description="Number of vulnerability categories to include per agent."
    ),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> AgentBehaviorResponse:
    try:
        report = analytics_service.agent_behavior_report(
            time_window=time_window,
            agent_id=agent_id,
            top_categories=top_categories,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return AgentBehaviorResponse(report=report, request_id=f"rq_{uuid.uuid4().hex}")
