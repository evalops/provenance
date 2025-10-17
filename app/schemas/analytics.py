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


class ReviewAlert(BaseModel):
    agent_id: str
    bot_block_overrides: int
    force_push_after_approval: int
    human_reviewer_count: int
    bot_block_events: int
    merge_actor: str | None = None
    merged_at: str | None = None
    override_details: list[dict] = Field(default_factory=list)


class ReviewAlertResponse(BaseModel):
    alerts: list[ReviewAlert]
    request_id: str


class ReviewLoadEntry(BaseModel):
    agent_id: str
    human_reviewers: int
    bot_reviews: int
    bot_block_events: int
    human_reviewer_teams: dict[str, int] = Field(default_factory=dict)


class ReviewLoadResponse(BaseModel):
    load: list[ReviewLoadEntry]
    request_id: str


class TeamReviewLoadEntry(BaseModel):
    team: str
    human_reviewers: int


class TeamReviewLoadResponse(BaseModel):
    load: list[TeamReviewLoadEntry]
    request_id: str


class TeamBudgetAlert(BaseModel):
    team: str
    human_reviewers: int
    budget: int
    overage: int


class TeamBudgetResponse(BaseModel):
    alerts: list[TeamBudgetAlert]
    request_id: str


class CIFailureEntry(BaseModel):
    name: str
    count: int
    agent_id: str | None = None


class CIFailureHeatmapResponse(BaseModel):
    failures: list[CIFailureEntry]
    request_id: str


class ReviewerDriftEntry(BaseModel):
    agent_id: str
    human_reviewers: int
    bot_reviews: int
    ratio: float
    human_reviewer_teams: dict[str, int] = Field(default_factory=dict)


class ReviewerDriftResponse(BaseModel):
    drifts: list[ReviewerDriftEntry]
    request_id: str
