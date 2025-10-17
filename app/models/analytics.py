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
    review_comment_count: int = Field(0, description="Total PR review comments in the window.")
    unique_reviewers: int = Field(0, description="Unique reviewer count across associated PRs.")
    review_events: int = Field(0, description="Total review submissions across associated PRs.")
    agent_comment_mentions: int = Field(0, description="Count of agent markers found in review comments.")
    comment_threads: int = Field(0, description="Distinct review discussion threads observed.")
    reopened_threads: int = Field(0, description="Threads where reviewers re-engaged after an agent response.")
    agent_response_rate: float = Field(0.0, description="Share of threads with an agent response.")
    agent_response_p50_hours: Optional[float] = Field(
        None, description="Median response time (hours) between reviewer comment and agent reply."
    )
    agent_response_p90_hours: Optional[float] = Field(
        None, description="P90 response time (hours) between reviewer comment and agent reply."
    )
    classification_breakdown: dict[str, int] = Field(
        default_factory=dict, description="Aggregate comment/review classifications (security, nit, etc.)."
    )
    human_reviewer_count: int = Field(0, description="Count of human reviewers engaged across PRs in the window.")
    reviewer_association_breakdown: dict[str, int] = Field(
        default_factory=dict, description="Reviewer participation by GitHub association (member, contributor, etc.)."
    )
    human_reviewer_teams: dict[str, int] = Field(
        default_factory=dict, description="Human reviewer counts grouped by mapped team.")
    bot_review_events: int = Field(0, description="Total bot-authored review submissions.")
    bot_block_events: int = Field(0, description="Bot reviews that requested changes.")
    bot_informational_events: int = Field(0, description="Bot reviews that left non-blocking feedback.")
    bot_approval_events: int = Field(0, description="Bot approvals recorded in the window.")
    bot_block_overrides: int = Field(0, description="Bot change requests overridden by merge without subsequent approval.")
    bot_block_resolved: int = Field(0, description="Bot change requests later satisfied by bot approval/dismissal.")
    bot_reviewer_count: int = Field(0, description="Unique bot reviewers participating.")
    bot_blocking_reviewer_count: int = Field(0, description="Unique bots that issued blocking reviews.")
    bot_informational_only_reviewer_count: int = Field(0, description="Bots that only left informational comments.")
    bot_comment_count: int = Field(0, description="Bot-authored review comments captured in conversations.")
    ci_run_count: int = Field(0, description="Number of CI runs/checks evaluated.")
    ci_failure_count: int = Field(0, description="Number of failing CI runs/checks.")
    ci_failed_checks: int = Field(0, description="Unique failing CI checks in the window.")
    ci_time_to_green_hours: Optional[float] = Field(None, description="Median time-to-green across CI runs.")
    ci_latest_status: Optional[str] = Field(None, description="Most recent CI rollup status observed.")
    force_push_events: int = Field(0, description="Force-push events recorded on associated PRs.")
    rewrite_loops: int = Field(0, description="Follow-up human commits arriving within 48h of agent commits.")
    human_followup_commits: int = Field(0, description="Count of human commits landing immediately after agent commits.")
    human_followup_commits_fast: int = Field(
        0, description="Human follow-up commits landing within 1 hour of an agent commit."
    )
    agent_commit_ratio: float = Field(0.0, description="Share of commits authored by the agent.")
    commit_lead_time_hours: Optional[float] = Field(None, description="Lead time between earliest and latest commits.")
    force_push_after_approval_count: int = Field(
        0, description="Number of analyses where a force-push occurred after approval."
    )
    ci_failed_check_names: dict[str, int] = Field(
        default_factory=dict, description="Counts of failing CI check names across the window."
    )
    ci_failure_contexts: dict[str, int] = Field(
        default_factory=dict, description="Counts of failing status contexts across the window."
    )
    top_paths: dict[str, int] = Field(
        default_factory=dict, description="Most frequently modified top-level paths for the agent."
    )
    hot_files: list[str] = Field(
        default_factory=list, description="Files touched repeatedly (>=3 times) signalling attention hot-spots."
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
