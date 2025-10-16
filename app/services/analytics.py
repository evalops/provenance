"""Analytics computations for provenance and risk metrics."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import re

from app.models.analytics import AnalyticsSeries, MetricPoint
from app.models.domain import AnalysisRecord, ChangedLine, Finding
from app.repositories.redis_store import RedisWarehouse


WINDOW_PATTERN = re.compile(r"^(?P<value>\d+)(?P<unit>[hdw])$")


def _parse_window(window: str) -> timedelta:
    match = WINDOW_PATTERN.match(window)
    if not match:
        raise ValueError(f"Invalid time window format: {window}")
    value = int(match.group("value"))
    unit = match.group("unit")
    match unit:
        case "h":
            return timedelta(hours=value)
        case "d":
            return timedelta(days=value)
        case "w":
            return timedelta(weeks=value)
    raise ValueError(f"Unsupported time window unit: {unit}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AnalyticsService:
    """Produces aggregated analytics for reporting and governance."""

    def __init__(self, store: RedisWarehouse) -> None:
        self._store = store

    def index_analysis(
        self,
        record: AnalysisRecord,
        lines: list[ChangedLine],
        findings: list[Finding],
    ) -> None:
        # Placeholder for future streaming functionality.
        return None

    def query_series(
        self,
        time_window: str,
        metric: str,
        group_by: str,
        category: str | None = None,
        agent_id: str | None = None,
    ) -> AnalyticsSeries:
        if group_by != "agent_id":
            raise ValueError("Only group_by=agent_id is currently supported.")

        window = _parse_window(time_window)
        window_end = _now()
        window_start = window_end - window
        analyses = [
            analysis
            for analysis in self._store.list_analyses()
            if analysis.created_at >= window_start and analysis.status == analysis.status.COMPLETED
        ]

        if metric == "risk_rate":
            return self._compute_risk_rate(analyses, window_start, window_end, category, agent_id)
        if metric == "provenance_coverage":
            return self._compute_provenance_coverage(analyses, window_start, window_end, agent_id)
        raise ValueError(f"Unsupported metric: {metric}")

    def _compute_risk_rate(
        self,
        analyses: list[AnalysisRecord],
        window_start: datetime,
        window_end: datetime,
        category: str | None,
        agent_filter: str | None,
    ) -> AnalyticsSeries:
        numerator: dict[str, int] = defaultdict(int)
        denominator: dict[str, int] = defaultdict(int)
        for analysis in analyses:
            lines = self._store.get_changed_lines(analysis.analysis_id)
            findings = self._store.list_findings(analysis.analysis_id)
            for line in lines:
                agent_id = line.attribution.agent.agent_id
                if agent_filter and agent_id != agent_filter:
                    continue
                denominator[agent_id] += 1
            for finding in findings:
                agent_id = finding.attribution.agent.agent_id
                if agent_filter and agent_id != agent_filter:
                    continue
                if category and finding.category != category:
                    continue
                numerator[agent_id] += 1
        points: list[MetricPoint] = []
        for agent_id, total_lines in denominator.items():
            finding_count = numerator.get(agent_id, 0)
            rate = (finding_count / total_lines) * 1000 if total_lines else 0.0
            points.append(
                MetricPoint(
                    metric="risk_rate",
                    agent_id=agent_id,
                    value=rate,
                    numerator=finding_count,
                    denominator=total_lines,
                    category=category,
                    window_start=window_start,
                    window_end=window_end,
                )
            )
        return AnalyticsSeries(metric="risk_rate", group_by="agent_id", data=sorted(points, key=lambda p: p.agent_id))

    def _compute_provenance_coverage(
        self,
        analyses: list[AnalysisRecord],
        window_start: datetime,
        window_end: datetime,
        agent_filter: str | None,
    ) -> AnalyticsSeries:
        known_counts: dict[str, int] = defaultdict(int)
        total_counts: dict[str, int] = defaultdict(int)
        for analysis in analyses:
            lines = self._store.get_changed_lines(analysis.analysis_id)
            for line in lines:
                agent_id = line.attribution.agent.agent_id or "unknown"
                if agent_filter and agent_id != agent_filter:
                    continue
                total_counts[agent_id] += 1
                if line.attribution.agent.agent_id:
                    known_counts[agent_id] += 1
        points: list[MetricPoint] = []
        for agent_id, total in total_counts.items():
            known = known_counts.get(agent_id, 0)
            coverage = (known / total) * 100 if total else 0.0
            points.append(
                MetricPoint(
                    metric="provenance_coverage",
                    agent_id=agent_id,
                    value=coverage,
                    numerator=known,
                    denominator=total,
                    window_start=window_start,
                    window_end=window_end,
                )
            )
        return AnalyticsSeries(
            metric="provenance_coverage",
            group_by="agent_id",
            data=sorted(points, key=lambda p: p.agent_id),
        )
