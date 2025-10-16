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
    unit: Optional[str] = Field(None, description="Optional unit for value (e.g., per_1000_lines).")


class AnalyticsSeries(BaseModel):
    """A collection of metric points returned to clients."""

    metric: str
    group_by: str
    data: list[MetricPoint] = Field(default_factory=list)


class AgentBehaviorSnapshot(BaseModel):
    """Composite analytics for a single agent within a window."""

    agent_id: str
    code_volume: int = Field(description="Total changed lines attributed to the agent.")
    churn_lines: int = Field(description="Lines modified or deleted by the agent.")
    churn_rate: float = Field(description="Churn ratio relative to total changed lines (0-1).")
    avg_line_complexity: float = Field(
        description="Heuristic complexity score based on average non-whitespace character count."
    )
    max_line_complexity: float = Field(
        description="Maximum heuristic complexity observed for a single line within the window."
    )
    top_vulnerability_categories: dict[str, int] = Field(
        default_factory=dict, description="Most frequent finding categories."
    )
    findings_by_severity: dict[str, int] = Field(
        default_factory=dict, description="Finding counts bucketed by severity."
    )


class AgentBehaviorReport(BaseModel):
    """Collection of behavior snapshots for multiple agents."""

    window_start: datetime
    window_end: datetime
    snapshots: list[AgentBehaviorSnapshot] = Field(default_factory=list)


class AnalyticsQuery(BaseModel):
    """Parameters used to slice and aggregate analytics data."""

    time_window: str
    metric: str
    group_by: str
    category: Optional[str] = None
    agent_id: Optional[str] = None
