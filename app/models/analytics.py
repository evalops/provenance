"""Analytics-facing models for reporting APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class MetricPoint(BaseModel):
    """Represents a single aggregated metric value."""

    metric: str
    agent_id: str
    value: float
    numerator: int
    denominator: int
    category: Optional[str] = None
    severity: Optional[str] = None
    window_start: datetime
    window_end: datetime


class AnalyticsSeries(BaseModel):
    """A collection of metric points returned to clients."""

    metric: str
    group_by: str
    data: list[MetricPoint] = Field(default_factory=list)


class AnalyticsQuery(BaseModel):
    """Parameters used to slice and aggregate analytics data."""

    time_window: str
    metric: str
    group_by: str
    category: Optional[str] = None
    agent_id: Optional[str] = None
