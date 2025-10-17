from datetime import datetime, timedelta, timezone

import fakeredis
import pytest

from app.models.domain import (
    AnalysisRecord,
    AnalysisStatus,
    AgentIdentity,
    ChangeType,
    ChangedLine,
    Finding,
    FindingStatus,
    ProvenanceAttribution,
    SeverityLevel,
)
from app.repositories.redis_store import RedisWarehouse
from app.services.analytics import AnalyticsService


def _bootstrap_store() -> AnalyticsService:
    now = datetime.now(timezone.utc) - timedelta(hours=12)
    store = RedisWarehouse(fakeredis.FakeRedis(decode_responses=True))
    analytics = AnalyticsService(store)

    # Analysis 1 - agent claude-3-opus
    record1 = AnalysisRecord(
        analysis_id="an-1",
        status=AnalysisStatus.COMPLETED,
        repo_id="acme/shop",
        pr_number="101",
        base_sha="abc",
        head_sha="def",
        created_at=now,
        updated_at=now,
        provenance_inputs={
            "github_metadata": {
                "review_summary": {
                    "review_comment_count": 2,
                    "unique_reviewers": 1,
                    "review_events": 1,
                    "agent_comment_mentions": 1,
                    "time_to_first_review_hours": 1.5,
                    "time_to_first_approval_hours": 2.0,
                    "time_to_merge_hours": 5.0,
                    "reviewer_profiles": [
                        {"login": "reviewer-a", "type": "User", "association": "MEMBER"}
                    ],
                    "approvals": 1,
                    "requested_changes": 0,
                    "comment_threads": 1,
                    "reopened_threads": 0,
                    "classification_breakdown": {"security": 1, "general": 1},
                    "agent_response_rate": 1.0,
                    "agent_response_p50_hours": 0.5,
                    "agent_response_p90_hours": 0.5,
                },
                "ci_summary": {
                    "run_count": 2,
                    "failure_count": 1,
                    "status_contexts": [
                        {"context": "deploy-ci", "state": "failure"}
                    ],
                    "check_runs": [
                        {
                            "name": "lint",
                            "status": "completed",
                            "conclusion": "failure",
                            "started_at": "2024-01-01T00:00:00+00:00",
                            "completed_at": "2024-01-01T00:03:00+00:00",
                        }
                    ],
                    "time_to_green_hours": 3.0,
                    "latest_status": "success",
                    "failed_checks": ["lint"],
                },
                "timeline_summary": {
                    "force_pushes": 1,
                    "reopens": 0,
                    "merge_events": 1,
                    "review_requests": 1,
                    "review_dismissals": 0,
                    "last_force_push_at": "2024-01-01T00:30:00+00:00",
                    "last_reopen_at": None,
                    "last_merge_at": "2024-01-01T05:00:00+00:00",
                    "last_review_request_at": "2024-01-01T00:01:00+00:00",
                    "ready_for_review_at": "2024-01-01T00:05:00+00:00",
                    "converted_to_draft_at": None,
                },
                "commit_summary": {
                    "total_commits": 3,
                    "agent_commits": 2,
                    "human_commits": 1,
                    "unique_authors": 2,
                    "revert_commits": 0,
                    "force_push_events": 1,
                    "human_followup_commits": 1,
                    "human_followup_commits_fast": 1,
                    "rewrite_loops": 1,
                    "agent_commit_ratio": 0.66,
                    "lead_time_hours": 6.0,
                    "force_push_after_approval": True,
                },
            }
        },
    )
    store.create_analysis(record1)
    claude = AgentIdentity(agent_id="claude-3-opus")
    lines_agent1 = [
        ChangedLine(
            analysis_id=record1.analysis_id,
            repo_id=record1.repo_id,
            pr_number=record1.pr_number,
            head_sha=record1.head_sha,
            file_path="services/orders.py",
            line_number=30 + idx,
            change_type=change_type,
            timestamp=now,
            branch="feature/analytics",
            language="python",
            content=content,
            attribution=ProvenanceAttribution(agent=claude),
        )
        for idx, (change_type, content) in enumerate(
            [
                (ChangeType.ADDED, "query = build_query(user_input)"),
                (ChangeType.MODIFIED, "query = sanitize(user_input)"),
                (ChangeType.DELETED, "dangerous_call()"),
            ]
        )
    ]
    store.add_changed_lines(record1.analysis_id, lines_agent1)
    finding1 = Finding(
        finding_id="fd-1",
        analysis_id=record1.analysis_id,
        repo_id=record1.repo_id,
        pr_number=record1.pr_number,
        file_path=lines_agent1[0].file_path,
        line_number=lines_agent1[0].line_number,
        rule_key="sql-injection-concat",
        rule_version="1.0.0",
        category="sqli",
        severity=SeverityLevel.HIGH,
        engine_name="semgrep",
        message="risk",
        detected_at=now,
        status=FindingStatus.OPEN,
        attribution=lines_agent1[0].attribution,
    )
    store.add_findings(record1.analysis_id, [finding1])

    # Analysis 2 - agent github-copilot
    record2_time = now + timedelta(hours=2)
    record2 = AnalysisRecord(
        analysis_id="an-2",
        status=AnalysisStatus.COMPLETED,
        repo_id="acme/shop",
        pr_number="102",
        base_sha="ghi",
        head_sha="jkl",
        created_at=record2_time,
        updated_at=record2_time,
        provenance_inputs={
            "github_metadata": {
                "review_summary": {
                    "review_comment_count": 3,
                    "unique_reviewers": 2,
                    "review_events": 2,
                    "agent_comment_mentions": 0,
                    "time_to_first_review_hours": 0.5,
                    "time_to_first_approval_hours": 1.0,
                    "time_to_merge_hours": 4.0,
                    "reviewer_profiles": [
                        {"login": "reviewer-b", "type": "User", "association": "MEMBER"},
                        {"login": "reviewer-c", "type": "User", "association": "CONTRIBUTOR"},
                    ],
                    "approvals": 1,
                    "requested_changes": 1,
                    "comment_threads": 2,
                    "reopened_threads": 1,
                    "classification_breakdown": {"nit": 1, "question": 1, "general": 1},
                    "agent_response_rate": 0.5,
                    "agent_response_p50_hours": 1.0,
                    "agent_response_p90_hours": 1.5,
                },
                "ci_summary": {
                    "run_count": 1,
                    "failure_count": 0,
                    "status_contexts": [
                        {"context": "deploy-ci", "state": "success"}
                    ],
                    "check_runs": [
                        {
                            "name": "integration",
                            "status": "completed",
                            "conclusion": "success",
                            "started_at": "2024-01-02T00:00:00+00:00",
                            "completed_at": "2024-01-02T00:05:00+00:00",
                        }
                    ],
                    "time_to_green_hours": 1.0,
                    "latest_status": "success",
                    "failed_checks": [],
                },
                "timeline_summary": {
                    "force_pushes": 0,
                    "reopens": 1,
                    "merge_events": 1,
                    "review_requests": 2,
                    "review_dismissals": 0,
                    "last_force_push_at": None,
                    "last_reopen_at": "2024-01-02T01:00:00+00:00",
                    "last_merge_at": "2024-01-02T02:00:00+00:00",
                    "last_review_request_at": "2024-01-02T00:10:00+00:00",
                    "ready_for_review_at": "2024-01-02T00:15:00+00:00",
                    "converted_to_draft_at": None,
                },
                "commit_summary": {
                    "total_commits": 2,
                    "agent_commits": 1,
                    "human_commits": 1,
                    "unique_authors": 2,
                    "revert_commits": 0,
                    "force_push_events": 0,
                    "human_followup_commits": 1,
                    "human_followup_commits_fast": 0,
                    "rewrite_loops": 0,
                    "agent_commit_ratio": 0.5,
                    "lead_time_hours": 2.0,
                    "force_push_after_approval": False,
                },
            }
        },
    )
    store.create_analysis(record2)
    copilot = AgentIdentity(agent_id="github-copilot")
    lines_agent2 = [
        ChangedLine(
            analysis_id=record2.analysis_id,
            repo_id=record2.repo_id,
            pr_number=record2.pr_number,
            head_sha=record2.head_sha,
            file_path="web/forms.ts",
            line_number=90 + idx,
            change_type=ChangeType.ADDED,
            timestamp=record2_time,
            branch="feature/forms",
            language="typescript",
            content=content,
            attribution=ProvenanceAttribution(agent=copilot),
        )
        for idx, content in enumerate(
            [
                "const payload = { email, password };",
                "submit(payload);",
                "return true;",
            ]
        )
    ]
    store.add_changed_lines(record2.analysis_id, lines_agent2)
    findings_agent2 = [
        Finding(
            finding_id="fd-2",
            analysis_id=record2.analysis_id,
            repo_id=record2.repo_id,
            pr_number=record2.pr_number,
            file_path=lines_agent2[1].file_path,
            line_number=lines_agent2[1].line_number,
            rule_key="dangerous-eval",
            rule_version="1.0.0",
            category="code_execution",
            severity=SeverityLevel.MEDIUM,
            engine_name="semgrep",
            message="eval usage",
            detected_at=record2_time,
            status=FindingStatus.OPEN,
            attribution=lines_agent2[1].attribution,
        ),
        Finding(
            finding_id="fd-3",
            analysis_id=record2.analysis_id,
            repo_id=record2.repo_id,
            pr_number=record2.pr_number,
            file_path=lines_agent2[2].file_path,
            line_number=lines_agent2[2].line_number,
            rule_key="dangerous-eval",
            rule_version="1.0.0",
            category="code_execution",
            severity=SeverityLevel.MEDIUM,
            engine_name="semgrep",
            message="eval usage again",
            detected_at=record2_time,
            status=FindingStatus.OPEN,
            attribution=lines_agent2[2].attribution,
        ),
    ]
    store.add_findings(record2.analysis_id, findings_agent2)
    return analytics


def test_risk_rate_aggregation_by_agent():
    analytics = _bootstrap_store()
    series = analytics.query_series(time_window="1d", metric="risk_rate", group_by="agent_id")

    assert series.metric == "risk_rate"
    assert len(series.data) == 2
    claude = next(point for point in series.data if point.agent_id == "claude-3-opus")
    copilot = next(point for point in series.data if point.agent_id == "github-copilot")
    assert claude.numerator == 1
    assert claude.denominator == 3
    assert claude.value == pytest.approx(333.333, rel=1e-3)
    assert copilot.numerator == 2
    assert copilot.denominator == 3
    assert copilot.value == pytest.approx(666.666, rel=1e-3)


def test_volume_churn_and_complexity_metrics():
    analytics = _bootstrap_store()
    volume_series = analytics.query_series(time_window="1d", metric="code_volume", group_by="agent_id")
    churn_series = analytics.query_series(time_window="1d", metric="code_churn_rate", group_by="agent_id")
    complexity_series = analytics.query_series(time_window="1d", metric="avg_line_complexity", group_by="agent_id")

    claude_volume = next(point for point in volume_series.data if point.agent_id == "claude-3-opus")
    assert claude_volume.value == 3.0
    assert claude_volume.unit == "lines"

    claude_churn = next(point for point in churn_series.data if point.agent_id == "claude-3-opus")
    assert claude_churn.numerator == 2  # modified + deleted
    assert claude_churn.denominator == 3
    assert claude_churn.unit == "percent"
    assert claude_churn.value == pytest.approx(66.666, rel=1e-3)

    copilot_complexity = next(point for point in complexity_series.data if point.agent_id == "github-copilot")
    assert copilot_complexity.unit == "avg_non_whitespace_chars"
    assert copilot_complexity.value > 0


def test_agent_behavior_report_highlights_top_categories():
    analytics = _bootstrap_store()
    report = analytics.agent_behavior_report(time_window="1d", top_categories=2)

    assert report.snapshots
    claude_snapshot = next(s for s in report.snapshots if s.agent_id == "claude-3-opus")
    assert claude_snapshot.code_volume == 3
    assert claude_snapshot.churn_lines == 2
    assert claude_snapshot.churn_rate == pytest.approx(2 / 3, rel=1e-6)
    assert claude_snapshot.top_vulnerability_categories == {"sqli": 1}
    assert claude_snapshot.max_line_complexity > 0
    assert claude_snapshot.findings_by_severity == {"high": 1}
    assert claude_snapshot.review_comment_count == 2
    assert claude_snapshot.unique_reviewers == 1
    assert claude_snapshot.review_events == 1
    assert claude_snapshot.agent_comment_mentions == 1
    assert claude_snapshot.comment_threads == 1
    assert claude_snapshot.reopened_threads == 0
    assert claude_snapshot.agent_response_rate == pytest.approx(1.0)
    assert claude_snapshot.agent_response_p50_hours == pytest.approx(0.5)
    assert claude_snapshot.agent_response_p90_hours == pytest.approx(0.5)
    assert claude_snapshot.classification_breakdown == {"security": 1, "general": 1}
    assert claude_snapshot.ci_run_count == 2
    assert claude_snapshot.ci_failure_count == 1
    assert claude_snapshot.ci_failed_checks == 1
    assert claude_snapshot.ci_time_to_green_hours == pytest.approx(3.0)
    assert claude_snapshot.ci_latest_status == "success"
    assert claude_snapshot.force_push_events == 1
    assert claude_snapshot.rewrite_loops == 1
    assert claude_snapshot.human_followup_commits == 1
    assert claude_snapshot.human_followup_commits_fast == 1
    assert claude_snapshot.agent_commit_ratio == pytest.approx(0.66, rel=1e-2)
    assert claude_snapshot.commit_lead_time_hours == pytest.approx(6.0)
    assert claude_snapshot.human_reviewer_count == 1
    assert claude_snapshot.reviewer_association_breakdown == {"member": 1}
    assert claude_snapshot.force_push_after_approval_count == 1
    assert claude_snapshot.ci_failed_check_names == {"lint": 1}
    assert claude_snapshot.ci_failure_contexts == {"deploy-ci": 1}
    assert claude_snapshot.bot_review_events == 0
    assert claude_snapshot.bot_block_events == 0
    assert claude_snapshot.bot_informational_events == 0
    assert claude_snapshot.bot_approval_events == 0
    assert claude_snapshot.bot_block_overrides == 0
    assert claude_snapshot.bot_block_resolved == 0
    assert claude_snapshot.bot_reviewer_count == 0
    assert claude_snapshot.bot_blocking_reviewer_count == 0
    assert claude_snapshot.bot_informational_only_reviewer_count == 0
    assert claude_snapshot.bot_comment_count == 0
    assert claude_snapshot.top_paths == {"services": 3}
    assert claude_snapshot.hot_files == ["services/orders.py"]

    copilot_snapshot = next(s for s in report.snapshots if s.agent_id == "github-copilot")
    assert copilot_snapshot.top_vulnerability_categories == {"code_execution": 2}
    assert copilot_snapshot.avg_line_complexity > 0
    assert copilot_snapshot.findings_by_severity == {"medium": 2}
    assert copilot_snapshot.review_comment_count == 3
    assert copilot_snapshot.unique_reviewers == 2
    assert copilot_snapshot.review_events == 2
    assert copilot_snapshot.agent_comment_mentions == 0
    assert copilot_snapshot.comment_threads == 2
    assert copilot_snapshot.reopened_threads == 1
    assert copilot_snapshot.agent_response_rate == pytest.approx(0.5)
    assert copilot_snapshot.agent_response_p50_hours == pytest.approx(1.0)
    assert copilot_snapshot.agent_response_p90_hours == pytest.approx(1.5)
    assert copilot_snapshot.classification_breakdown == {"general": 1, "nit": 1, "question": 1}
    assert copilot_snapshot.ci_run_count == 1
    assert copilot_snapshot.ci_failure_count == 0
    assert copilot_snapshot.ci_failed_checks == 0
    assert copilot_snapshot.ci_time_to_green_hours == pytest.approx(1.0)
    assert copilot_snapshot.ci_latest_status == "success"
    assert copilot_snapshot.force_push_events == 0
    assert copilot_snapshot.rewrite_loops == 0
    assert copilot_snapshot.human_followup_commits == 1
    assert copilot_snapshot.human_followup_commits_fast == 0
    assert copilot_snapshot.agent_commit_ratio == pytest.approx(0.5)
    assert copilot_snapshot.commit_lead_time_hours == pytest.approx(2.0)
    assert copilot_snapshot.human_reviewer_count == 2
    assert copilot_snapshot.reviewer_association_breakdown == {"member": 1, "contributor": 1}
    assert copilot_snapshot.force_push_after_approval_count == 0
    assert copilot_snapshot.ci_failed_check_names == {}
    assert copilot_snapshot.ci_failure_contexts == {}
    assert copilot_snapshot.bot_review_events == 0
    assert copilot_snapshot.bot_block_events == 0
    assert copilot_snapshot.bot_informational_events == 0
    assert copilot_snapshot.bot_approval_events == 0
    assert copilot_snapshot.bot_block_overrides == 0
    assert copilot_snapshot.bot_block_resolved == 0
    assert copilot_snapshot.bot_reviewer_count == 0
    assert copilot_snapshot.bot_blocking_reviewer_count == 0
    assert copilot_snapshot.bot_informational_only_reviewer_count == 0
    assert copilot_snapshot.bot_comment_count == 0
    assert copilot_snapshot.top_paths == {"web": 3}
    assert copilot_snapshot.hot_files == ["web/forms.ts"]


def test_mttr_and_suppression_metrics():
    analytics = _bootstrap_store()
    store = analytics._store  # type: ignore[attr-defined]
    now = datetime.now(timezone.utc)

    suppressed = Finding(
        finding_id="fd-suppressed",
        analysis_id="an-1",
        repo_id="acme/shop",
        pr_number="101",
        file_path="services/orders.py",
        line_number=99,
        rule_key="suppression",
        rule_version="1.0.0",
        category="code_execution",
        severity=SeverityLevel.MEDIUM,
        engine_name="ext",
        message="suppressed",
        detected_at=now,
        status=FindingStatus.SUPPRESSED,
        attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="claude-3-opus")),
    )
    store.add_findings("an-1", [suppressed])

    remediated = Finding(
        finding_id="fd-remediated",
        analysis_id="an-2",
        repo_id="acme/shop",
        pr_number="102",
        file_path="web/forms.ts",
        line_number=120,
        rule_key="remediation",
        rule_version="1.0.0",
        category="code_execution",
        severity=SeverityLevel.MEDIUM,
        engine_name="ext",
        message="remediated",
        detected_at=now - timedelta(hours=5),
        remediated_at=now,
        status=FindingStatus.REMEDIATED,
        attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="github-copilot")),
    )
    store.add_findings("an-2", [remediated])

    mttr_series = analytics.query_series(time_window="1d", metric="mttr", group_by="agent_id")
    suppression_series = analytics.query_series(time_window="1d", metric="suppression_rate", group_by="agent_id")
    review_series = analytics.query_series(time_window="1d", metric="review_comments", group_by="agent_id")
    reviewer_series = analytics.query_series(time_window="1d", metric="unique_reviewers", group_by="agent_id")
    response_series = analytics.query_series(time_window="1d", metric="agent_response_rate", group_by="agent_id")
    force_push_series = analytics.query_series(time_window="1d", metric="force_push_events", group_by="agent_id")
    rewrite_series = analytics.query_series(time_window="1d", metric="rewrite_loops", group_by="agent_id")
    ci_green_series = analytics.query_series(time_window="1d", metric="ci_time_to_green_hours", group_by="agent_id")
    classification_series = analytics.query_series(time_window="1d", metric="classification_security_count", group_by="agent_id")
    followup_series = analytics.query_series(time_window="1d", metric="human_followup_commits", group_by="agent_id")
    commit_ratio_series = analytics.query_series(time_window="1d", metric="agent_commit_ratio", group_by="agent_id")
    human_reviewer_series = analytics.query_series(time_window="1d", metric="human_reviewer_count", group_by="agent_id")
    avg_human_reviewer_series = analytics.query_series(time_window="1d", metric="avg_human_reviewers", group_by="agent_id")
    force_push_after_series = analytics.query_series(time_window="1d", metric="force_push_after_approval", group_by="agent_id")
    human_followup_fast_series = analytics.query_series(time_window="1d", metric="human_followup_fast", group_by="agent_id")
    avg_unique_reviewer_series = analytics.query_series(time_window="1d", metric="avg_unique_reviewers", group_by="agent_id")
    bot_review_series = analytics.query_series(time_window="1d", metric="bot_review_events", group_by="agent_id")
    bot_block_series = analytics.query_series(time_window="1d", metric="bot_block_events", group_by="agent_id")
    bot_override_series = analytics.query_series(time_window="1d", metric="bot_block_overrides", group_by="agent_id")

    mttr_point = next(point for point in mttr_series.data if point.agent_id == "github-copilot")
    assert mttr_point.value == pytest.approx(5.0)

    suppression_point = next(point for point in suppression_series.data if point.agent_id == "claude-3-opus")
    assert suppression_point.value == pytest.approx(50.0)
    assert suppression_point.numerator == 1

    review_point = next(point for point in review_series.data if point.agent_id == "github-copilot")
    assert review_point.value == 3.0

    reviewer_point = next(point for point in reviewer_series.data if point.agent_id == "github-copilot")
    assert reviewer_point.value == 2.0

    response_point = next(point for point in response_series.data if point.agent_id == "github-copilot")
    assert response_point.value == pytest.approx(0.5)

    force_push_point = next(point for point in force_push_series.data if point.agent_id == "claude-3-opus")
    assert force_push_point.value == 1.0

    rewrite_point = next(point for point in rewrite_series.data if point.agent_id == "claude-3-opus")
    assert rewrite_point.value == 1.0

    ci_green_point = next(point for point in ci_green_series.data if point.agent_id == "claude-3-opus")
    assert ci_green_point.value == pytest.approx(3.0)

    classification_point = next(point for point in classification_series.data if point.agent_id == "claude-3-opus")
    assert classification_point.value == 1.0

    followup_point = next(point for point in followup_series.data if point.agent_id == "claude-3-opus")
    assert followup_point.value == 1.0

    commit_ratio_point = next(point for point in commit_ratio_series.data if point.agent_id == "github-copilot")
    assert commit_ratio_point.value == pytest.approx(0.5)

    human_reviewer_point = next(point for point in human_reviewer_series.data if point.agent_id == "github-copilot")
    assert human_reviewer_point.value == 2.0

    avg_human_reviewer_point = next(point for point in avg_human_reviewer_series.data if point.agent_id == "github-copilot")
    assert avg_human_reviewer_point.value == pytest.approx(2.0)

    force_push_after_point = next(point for point in force_push_after_series.data if point.agent_id == "claude-3-opus")
    assert force_push_after_point.value == 1.0

    human_followup_fast_point = next(point for point in human_followup_fast_series.data if point.agent_id == "claude-3-opus")
    assert human_followup_fast_point.value == 1.0

    avg_unique_reviewer_point = next(point for point in avg_unique_reviewer_series.data if point.agent_id == "github-copilot")
    assert avg_unique_reviewer_point.value == pytest.approx(2.0)

    bot_review_point = next(point for point in bot_review_series.data if point.agent_id == "github-copilot")
    assert bot_review_point.value == 0.0

    bot_block_point = next(point for point in bot_block_series.data if point.agent_id == "github-copilot")
    assert bot_block_point.value == 0.0

    bot_override_point = next(point for point in bot_override_series.data if point.agent_id == "claude-3-opus")
    assert bot_override_point.value == 0.0


def test_review_alert_detection_and_trend():
    analytics = _bootstrap_store()
    store = analytics._store  # type: ignore[attr-defined]
    now = datetime.now(timezone.utc) + timedelta(hours=3)

    override_record = AnalysisRecord(
        analysis_id="an-override",
        status=AnalysisStatus.COMPLETED,
        repo_id="acme/shop",
        pr_number="103",
        base_sha="base-3",
        head_sha="head-3",
        created_at=now,
        updated_at=now,
        provenance_inputs={
            "changed_lines": [],
            "github_metadata": {
                "review_summary": {
                    "bot_block_overrides": 2,
                    "bot_block_resolved": 1,
                    "bot_review_events": 3,
                    "bot_block_events": 2,
                    "bot_reviewer_count": 2,
                    "bot_comment_count": 4,
                    "human_reviewer_count": 1,
                },
                "commit_summary": {
                    "force_push_after_approval": False,
                },
            },
        },
    )
    store.create_analysis(override_record)
    store.add_changed_lines(
        override_record.analysis_id,
        [
            ChangedLine(
                analysis_id=override_record.analysis_id,
                repo_id=override_record.repo_id,
                pr_number=override_record.pr_number,
                head_sha=override_record.head_sha,
                file_path="services/orders.py",
                line_number=1,
                change_type=ChangeType.ADDED,
                timestamp=now,
                branch="feature/override",
                language="python",
                content="value = 1",
                attribution=ProvenanceAttribution(agent=AgentIdentity(agent_id="override-bot")),
            )
        ],
    )

    alerts = analytics.detect_review_alerts(time_window="2d")
    override_alert = next(alert for alert in alerts if alert["agent_id"] == "override-bot")
    assert override_alert["bot_block_overrides"] == 2
    assert override_alert["force_push_after_approval"] == 0

    trend = analytics.human_vs_bot_load(time_window="2d")
    override_trend = next(item for item in trend if item["agent_id"] == "override-bot")
    assert override_trend["bot_reviews"] == 3
    assert override_trend["human_reviewers"] == 1
