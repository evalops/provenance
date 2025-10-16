"""API schemas for analytics reporting."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.analytics import AnalyticsSeries, AgentBehaviorReport


class AnalyticsSummaryResponse(BaseModel):
    """Response for GET /v1/analytics/summary."""

    result: AnalyticsSeries
    request_id: str


class AgentBehaviorResponse(BaseModel):
    """Response for GET /v1/analytics/agents/behavior."""

    report: AgentBehaviorReport
    request_id: str


class AnalyticsQueryParams(BaseModel):
    """Validated query parameters for analytics endpoints."""

    time_window: str = Field(..., description="Duration string such as 7d, 24h.")
    metric: str = Field(..., description="Metric name, e.g. risk_rate or provenance_coverage.")
    group_by: str = Field(..., description="Grouping dimension, e.g. agent_id.")
    category: str | None = Field(None, description="Optional filter for rule category.")
    agent_id: str | None = Field(None, description="Optional filter for specific agent.")
