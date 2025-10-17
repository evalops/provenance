"""API routes for analytics reporting."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.config import settings
from app.dependencies import get_analytics_service
from app.schemas.analytics import (
    AnalyticsSummaryResponse,
    AgentBehaviorResponse,
    ReviewAlertResponse,
    ReviewLoadResponse,
    TeamReviewLoadResponse,
    TeamBudgetResponse,
    CIFailureHeatmapResponse,
    ReviewerDriftResponse,
)
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


@router.get("/review-alerts", response_model=ReviewAlertResponse)
def get_review_alerts(
    time_window: str = Query(..., description="Duration string such as 7d or 24h."),
    threshold: int = Query(1, ge=1, description="Minimum override/force-push count to surface."),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> ReviewAlertResponse:
    alerts = analytics_service.detect_review_alerts(time_window=time_window, threshold=threshold)
    return ReviewAlertResponse(alerts=alerts, request_id=f"rq_{uuid.uuid4().hex}")


@router.get("/review-load", response_model=ReviewLoadResponse)
def get_review_load(
    time_window: str = Query(..., description="Duration string such as 7d or 24h."),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> ReviewLoadResponse:
    load = analytics_service.human_vs_bot_load(time_window=time_window)
    return ReviewLoadResponse(load=load, request_id=f"rq_{uuid.uuid4().hex}")


@router.get("/review-load/teams", response_model=TeamReviewLoadResponse)
def get_team_review_load(
    time_window: str = Query(..., description="Duration string such as 7d or 24h."),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> TeamReviewLoadResponse:
    load = analytics_service.team_review_load(time_window=time_window)
    return TeamReviewLoadResponse(load=load, request_id=f"rq_{uuid.uuid4().hex}")


@router.get("/review-load/teams/alerts", response_model=TeamBudgetResponse)
def get_team_budget_alerts(
    time_window: str = Query(..., description="Duration string such as 7d or 24h."),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> TeamBudgetResponse:
    alerts = analytics_service.enforce_team_budgets(time_window=time_window)
    return TeamBudgetResponse(alerts=alerts, request_id=f"rq_{uuid.uuid4().hex}")


@router.get("/ci-failure-heatmap", response_model=CIFailureHeatmapResponse)
def get_ci_failure_heatmap(
    time_window: str = Query(..., description="Duration string such as 7d or 24h."),
    agent_id: str | None = Query(None, description="Optional filter for agent ID."),
    limit: int = Query(25, ge=1, le=100, description="Maximum number of entries to return."),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> CIFailureHeatmapResponse:
    failures = analytics_service.ci_failure_heatmap(time_window=time_window, agent_id=agent_id, limit=limit)
    return CIFailureHeatmapResponse(failures=failures, request_id=f"rq_{uuid.uuid4().hex}")


@router.get("/review-drift", response_model=ReviewerDriftResponse)
def get_reviewer_drift(
    time_window: str = Query(..., description="Duration string such as 7d or 24h."),
    human_threshold: int = Query(1, ge=1, description="Minimum human review count to flag drift."),
    ratio_threshold: float = Query(0.5, ge=0.0, description="Human:bot ratio threshold."),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> ReviewerDriftResponse:
    drifts = analytics_service.detect_reviewer_drift(
        time_window=time_window,
        human_threshold=human_threshold,
        ratio_threshold=ratio_threshold,
    )
    return ReviewerDriftResponse(drifts=drifts, request_id=f"rq_{uuid.uuid4().hex}")
