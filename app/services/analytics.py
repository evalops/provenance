"""Analytics computations for provenance and risk metrics."""

from __future__ import annotations

import ast
from collections import defaultdict
import statistics
from datetime import datetime, timedelta, timezone
import re

from app.models.analytics import AnalyticsSeries, MetricPoint, AgentBehaviorReport, AgentBehaviorSnapshot
from app.models.domain import AnalysisRecord, ChangedLine, Finding, ChangeType, FindingStatus
from app.repositories.redis_store import RedisWarehouse
from app.telemetry import EventSink, NullEventSink


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

    def __init__(self, store: RedisWarehouse, sink: EventSink | None = None) -> None:
        self._store = store
        self._sink = sink or NullEventSink()

    def index_analysis(
        self,
        record: AnalysisRecord,
        lines: list[ChangedLine],
        findings: list[Finding],
    ) -> None:
        event = self._build_timeseries_event(record, lines, findings)
        self._sink.publish(event)

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
        analyses = self._filter_analyses(window_start)

        if metric == "risk_rate":
            return self._compute_risk_rate(analyses, window_start, window_end, category, agent_id)
        if metric == "provenance_coverage":
            return self._compute_provenance_coverage(analyses, window_start, window_end, agent_id)
        if metric == "code_volume":
            return self._compute_code_volume(analyses, window_start, window_end, agent_id)
        if metric == "code_churn_rate":
            return self._compute_churn_rate(analyses, window_start, window_end, agent_id)
        if metric == "avg_line_complexity":
            return self._compute_avg_complexity(analyses, window_start, window_end, agent_id)
        if metric == "mttr":
            return self._compute_mttr(analyses, window_start, window_end, agent_id)
        if metric == "suppression_rate":
            return self._compute_suppression_rate(analyses, window_start, window_end, agent_id)
        raise ValueError(f"Unsupported metric: {metric}")

    def agent_behavior_report(
        self,
        time_window: str,
        agent_id: str | None = None,
        top_categories: int = 3,
    ) -> AgentBehaviorReport:
        window = _parse_window(time_window)
        window_end = _now()
        window_start = window_end - window
        analyses = self._filter_analyses(window_start)
        snapshots: list[AgentBehaviorSnapshot] = []
        lines_by_agent, findings_by_agent = self._collect_window_data(analyses, agent_id)
        for agent, lines in lines_by_agent.items():
            code_volume = len(lines)
            churn_lines = sum(1 for line in lines if line.change_type in {ChangeType.MODIFIED, ChangeType.DELETED})
            churn_rate = (churn_lines / code_volume) if code_volume else 0.0
            complexity_values = [self._line_complexity(line) for line in lines if (line.content or "").strip()]
            avg_complexity = (sum(complexity_values) / len(complexity_values)) if complexity_values else 0.0
            max_complexity = max(complexity_values) if complexity_values else 0.0
            category_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            for finding in findings_by_agent.get(agent, []):
                category_counts[finding.category] += 1
                severity_counts[finding.severity.value] += 1
            top_categories_map = dict(sorted(category_counts.items(), key=lambda item: item[1], reverse=True)[:top_categories])
            snapshots.append(
                AgentBehaviorSnapshot(
                    agent_id=agent,
                    code_volume=code_volume,
                    churn_lines=churn_lines,
                    churn_rate=churn_rate,
                    avg_line_complexity=avg_complexity,
                    max_line_complexity=max_complexity,
                    top_vulnerability_categories=top_categories_map,
                    findings_by_severity=dict(severity_counts),
                )
            )
        snapshots.sort(key=lambda snap: snap.agent_id)
        return AgentBehaviorReport(window_start=window_start, window_end=window_end, snapshots=snapshots)

    def _build_timeseries_event(
        self,
        record: AnalysisRecord,
        lines: list[ChangedLine],
        findings: list[Finding],
    ) -> dict:
        timestamp = _now().isoformat()
        agent_lines: dict[str, list[ChangedLine]] = defaultdict(list)
        agent_findings: dict[str, list[Finding]] = defaultdict(list)
        for line in lines:
            agent_id = line.attribution.agent.agent_id or "unknown"
            agent_lines[agent_id].append(line)
        for finding in findings:
            agent_id = finding.attribution.agent.agent_id or "unknown"
            agent_findings[agent_id].append(finding)

        agent_payloads: list[dict] = []
        total_lines = len(lines)
        total_findings = len(findings)
        for agent_id, agent_lines_list in agent_lines.items():
            agent_findings_list = agent_findings.get(agent_id, [])
            churn_lines = sum(
                1 for line in agent_lines_list if line.change_type in {ChangeType.MODIFIED, ChangeType.DELETED}
            )
            churn_rate = (churn_lines / len(agent_lines_list)) if agent_lines_list else 0.0
            complexity_values = [self._line_complexity(line) for line in agent_lines_list if (line.content or "").strip()]
            avg_complexity = (sum(complexity_values) / len(complexity_values)) if complexity_values else 0.0
            category_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            for finding in agent_findings_list:
                category_counts[finding.category] += 1
                severity_counts[finding.severity.value] += 1
            agent_payloads.append(
                {
                    "agent_id": agent_id,
                    "code_volume": len(agent_lines_list),
                    "churn_lines": churn_lines,
                    "churn_rate": churn_rate,
                    "avg_line_complexity": avg_complexity,
                    "max_line_complexity": max(complexity_values) if complexity_values else 0.0,
                    "findings_by_category": dict(category_counts),
                    "findings_by_severity": dict(severity_counts),
                }
            )

        agent_payloads.sort(key=lambda payload: payload["agent_id"])
        return {
            "event_type": "analysis_metrics",
            "analysis_id": record.analysis_id,
            "repo_id": record.repo_id,
            "pr_number": record.pr_number,
            "timestamp": timestamp,
            "total_lines": total_lines,
            "total_findings": total_findings,
            "agent_metrics": agent_payloads,
        }

    def _filter_analyses(self, window_start: datetime) -> list[AnalysisRecord]:
        return [
            analysis
            for analysis in self._store.list_analyses()
            if analysis.created_at >= window_start and analysis.status == analysis.status.COMPLETED
        ]

    def _collect_window_data(
        self, analyses: list[AnalysisRecord], agent_filter: str | None
    ) -> tuple[dict[str, list[ChangedLine]], dict[str, list[Finding]]]:
        lines_by_agent: dict[str, list[ChangedLine]] = defaultdict(list)
        findings_by_agent: dict[str, list[Finding]] = defaultdict(list)
        for analysis in analyses:
            lines = self._store.get_changed_lines(analysis.analysis_id)
            findings = self._store.list_findings(analysis.analysis_id)
            for line in lines:
                agent_id = line.attribution.agent.agent_id or "unknown"
                if agent_filter and agent_id != agent_filter:
                    continue
                lines_by_agent[agent_id].append(line)
            for finding in findings:
                agent_id = finding.attribution.agent.agent_id or "unknown"
                if agent_filter and agent_id != agent_filter:
                    continue
                findings_by_agent[agent_id].append(finding)
        return lines_by_agent, findings_by_agent

    @staticmethod
    def _line_complexity(line: ChangedLine) -> int:
        content = (line.content or "").strip()
        if not content:
            return 0
        language = (line.language or "").lower()
        if language == "python":
            try:
                tree = ast.parse(content)
            except SyntaxError:
                pass
            else:
                node_count = sum(1 for _ in ast.walk(tree))
                # Weight node count against character length to reflect structural complexity.
                return max(node_count, len(content))
        token_complexity = len([token for token in re.split(r"\W+", content) if token])
        symbol_complexity = sum(1 for char in content if char in "{}[]();,.")
        operator_complexity = sum(1 for char in content if char in "+-*/%=&|<>!?")
        return token_complexity + symbol_complexity + operator_complexity

    def _compute_code_volume(
        self,
        analyses: list[AnalysisRecord],
        window_start: datetime,
        window_end: datetime,
        agent_filter: str | None,
    ) -> AnalyticsSeries:
        lines_by_agent, _ = self._collect_window_data(analyses, agent_filter)
        points: list[MetricPoint] = []
        for agent, lines in lines_by_agent.items():
            total_lines = len(lines)
            points.append(
                MetricPoint(
                    metric="code_volume",
                    agent_id=agent,
                    value=float(total_lines),
                    numerator=total_lines,
                    denominator=1,
                    window_start=window_start,
                    window_end=window_end,
                    unit="lines",
                )
            )
        return AnalyticsSeries(metric="code_volume", group_by="agent_id", data=sorted(points, key=lambda p: p.agent_id))

    def _compute_churn_rate(
        self,
        analyses: list[AnalysisRecord],
        window_start: datetime,
        window_end: datetime,
        agent_filter: str | None,
    ) -> AnalyticsSeries:
        lines_by_agent, _ = self._collect_window_data(analyses, agent_filter)
        points: list[MetricPoint] = []
        for agent, lines in lines_by_agent.items():
            total_lines = len(lines)
            churn_lines = sum(1 for line in lines if line.change_type in {ChangeType.MODIFIED, ChangeType.DELETED})
            value = (churn_lines / total_lines) * 100 if total_lines else 0.0
            points.append(
                MetricPoint(
                    metric="code_churn_rate",
                    agent_id=agent,
                    value=value,
                    numerator=churn_lines,
                    denominator=total_lines if total_lines else 1,
                    window_start=window_start,
                    window_end=window_end,
                    unit="percent",
                )
            )
        return AnalyticsSeries(metric="code_churn_rate", group_by="agent_id", data=sorted(points, key=lambda p: p.agent_id))

    def _compute_avg_complexity(
        self,
        analyses: list[AnalysisRecord],
        window_start: datetime,
        window_end: datetime,
        agent_filter: str | None,
    ) -> AnalyticsSeries:
        lines_by_agent, _ = self._collect_window_data(analyses, agent_filter)
        points: list[MetricPoint] = []
        for agent, lines in lines_by_agent.items():
            complexity_values = [self._line_complexity(line) for line in lines if (line.content or "").strip()]
            total_complexity = sum(complexity_values)
            count = len(complexity_values)
            avg_complexity = (total_complexity / count) if count else 0.0
            points.append(
                MetricPoint(
                    metric="avg_line_complexity",
                    agent_id=agent,
                    value=avg_complexity,
                    numerator=int(total_complexity),
                    denominator=count if count else 1,
                    window_start=window_start,
                    window_end=window_end,
                    unit="avg_non_whitespace_chars",
                )
            )
        return AnalyticsSeries(
            metric="avg_line_complexity",
            group_by="agent_id",
            data=sorted(points, key=lambda p: p.agent_id),
        )

    def _compute_mttr(
        self,
        analyses: list[AnalysisRecord],
        window_start: datetime,
        window_end: datetime,
        agent_filter: str | None,
    ) -> AnalyticsSeries:
        _, findings_by_agent = self._collect_window_data(analyses, agent_filter)
        points: list[MetricPoint] = []
        for agent, findings in findings_by_agent.items():
            durations = [
                (finding.remediated_at - finding.detected_at).total_seconds()
                for finding in findings
                if finding.remediated_at
            ]
            if not durations:
                continue
            mttr_seconds = statistics.median(durations)
            points.append(
                MetricPoint(
                    metric="mttr",
                    agent_id=agent,
                    value=mttr_seconds / 3600,
                    numerator=int(mttr_seconds),
                    denominator=len(durations),
                    window_start=window_start,
                    window_end=window_end,
                    unit="hours",
                )
            )
        return AnalyticsSeries(metric="mttr", group_by="agent_id", data=sorted(points, key=lambda p: p.agent_id))

    def _compute_suppression_rate(
        self,
        analyses: list[AnalysisRecord],
        window_start: datetime,
        window_end: datetime,
        agent_filter: str | None,
    ) -> AnalyticsSeries:
        _, findings_by_agent = self._collect_window_data(analyses, agent_filter)
        points: list[MetricPoint] = []
        for agent, findings in findings_by_agent.items():
            total = len(findings)
            suppressed = sum(1 for finding in findings if finding.status == FindingStatus.SUPPRESSED)
            if total == 0:
                continue
            value = (suppressed / total) * 100
            points.append(
                MetricPoint(
                    metric="suppression_rate",
                    agent_id=agent,
                    value=value,
                    numerator=suppressed,
                    denominator=total,
                    window_start=window_start,
                    window_end=window_end,
                    unit="percent",
                )
            )
        return AnalyticsSeries(metric="suppression_rate", group_by="agent_id", data=sorted(points, key=lambda p: p.agent_id))

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
