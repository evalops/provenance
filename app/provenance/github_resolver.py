"""GitHub-backed provenance resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
import statistics
import math
from collections import defaultdict
from datetime import datetime, timezone, timedelta
import re
import time
from typing import Optional, Callable, Iterable, Sequence

from github import Github, GithubException, Commit
from github.Auth import Token

AGENT_TRAILER_PATTERN = re.compile(r"^Agent-ID:\s*(?P<agent>[^\s]+)", re.IGNORECASE)
CO_AUTHOR_PATTERN = re.compile(r"Co-authored-by:\s*(?P<author>.+)", re.IGNORECASE)


@dataclass(frozen=True)
class ThreadEvent:
    author: str | None
    created_at: datetime | None
    is_agent: bool


@dataclass
class ConversationComments:
    serialized: list[dict]
    thread_events: dict[str, list[ThreadEvent]]
    classification_counts: dict[str, int]
    unique_reviewers: set[str]
    agent_mentions: int
    reviewer_identities: dict[str, dict] = field(default_factory=dict)


@dataclass
class ConversationReviews:
    entries: list[dict]
    classification_counts: dict[str, int]
    unique_reviewers: set[str]
    approvals: int
    requested_changes: int
    first_review_time: datetime | None
    first_approval_time: datetime | None
    reviewer_identities: dict[str, dict] = field(default_factory=dict)


class GitHubProvenanceResolver:
    """Resolve agent attribution using GitHub commit and PR metadata."""

    def __init__(
        self,
        token: str,
        *,
        base_url: str | None = None,
        agent_label_prefix: str = "agent:",
        cache_ttl_seconds: int = 300,
        agent_map: dict[str, str] | None = None,
    ) -> None:
        self._agent_label_prefix = agent_label_prefix.lower()
        auth = Token(token)
        if base_url:
            self._client = Github(auth=auth, base_url=base_url.rstrip("/"))
        else:
            self._client = Github(auth=auth)
        self._cache_ttl = max(cache_ttl_seconds, 30)
        self._agent_map = {k.lower(): v for k, v in (agent_map or {}).items()}
        self._commit_cache: dict[tuple[str, str], tuple[float, Optional[Commit.Commit]]] = {}
        self._label_cache: dict[tuple[str, int], tuple[float, list[str]]] = {}
        self._comment_cache: dict[tuple[str, int], tuple[float, list[str]]] = {}
        self._reviewer_cache: dict[tuple[str, int], tuple[float, list[str]]] = {}
        self._review_event_cache: dict[tuple[str, int], tuple[float, int]] = {}
        self._pull_cache: dict[tuple[str, int], tuple[float, Optional[object]]] = {}
        self._checks_cache: dict[str, tuple[float, dict]] = {}
        self._timeline_cache: dict[tuple[str, int], tuple[float, dict]] = {}

    def resolve_agent(
        self,
        repo_full_name: str,
        pr_number: str | None,
        commit_sha: str | None,
    ) -> tuple[Optional[str], Optional[str], dict]:
        agent_id: Optional[str] = None
        session_id: Optional[str] = None
        evidence: dict = {"sources": []}

        if commit_sha:
            commit_agent, commit_session, commit_evidence = self._from_commit(repo_full_name, commit_sha)
        else:
            commit_agent, commit_session, commit_evidence = (None, None, {"source": "commit", "reason": "not_provided"})
        evidence["sources"].append(commit_evidence)
        if commit_agent:
            agent_id = commit_agent
        if commit_session:
            session_id = commit_session

        label_evidence = {"source": "label", "reason": "not_checked"}
        if pr_number:
            label_agent, label_evidence = self._from_pr_labels(repo_full_name, int(pr_number))
            if label_agent and not agent_id:
                agent_id = label_agent
        evidence["sources"].append(label_evidence)

        discussion_evidence = {"source": "discussion", "reason": "not_checked"}
        if pr_number:
            discussion_agent, discussion_evidence = self._from_pr_discussion(repo_full_name, int(pr_number))
            if discussion_agent and not agent_id:
                agent_id = discussion_agent
        evidence["sources"].append(discussion_evidence)

        body_evidence = {"source": "body", "reason": "not_checked"}
        if pr_number:
            body_agent, body_evidence = self._from_pr_body(repo_full_name, int(pr_number))
            if body_agent and not agent_id:
                agent_id = body_agent
        evidence["sources"].append(body_evidence)

        evidence["agent_id"] = agent_id
        return agent_id, session_id, evidence

    def review_stats(self, repo_full_name: str, pr_number: int) -> dict[str, int] | None:
        pr = self._get_pull(repo_full_name, pr_number)
        if not pr:
            return None
        conversation = self._build_conversation_snapshot(pr, set(self._agent_map.keys()))
        summary = conversation.get("summary", {})
        return summary or None

    def collect_pr_metadata(
        self,
        repo_full_name: str,
        pr_number: int,
        head_sha: str | None,
    ) -> dict:
        pr = self._get_pull(repo_full_name, pr_number)
        if not pr:
            return {}

        created_at = getattr(pr, "created_at", None)
        merged_at = getattr(pr, "merged_at", None)
        updated_at = getattr(pr, "updated_at", None)
        agent_logins = set(self._agent_map.keys())

        conversation = self._build_conversation_snapshot(pr, agent_logins)
        conversation_summary = conversation.get("summary", {})
        timeline = self._collect_timeline(repo_full_name, pr_number, pr)
        timeline_summary = timeline.get("summary", {})

        ready_for_review_iso = timeline_summary.get("ready_for_review_at")
        ready_for_review_at = self._parse_iso(ready_for_review_iso)
        first_review_iso = conversation_summary.get("first_review_submitted_at")
        first_review_at = self._parse_iso(first_review_iso)
        first_approval_iso = conversation_summary.get("first_approval_submitted_at")
        first_approval_at = self._parse_iso(first_approval_iso)

        if ready_for_review_at and created_at:
            conversation_summary["time_to_ready_for_review_hours"] = self._hours_between(created_at, ready_for_review_at)
        if ready_for_review_at and first_review_at:
            conversation_summary["ready_to_first_review_hours"] = self._hours_between(ready_for_review_at, first_review_at)
        if ready_for_review_at and merged_at:
            conversation_summary["ready_to_merge_hours"] = self._hours_between(ready_for_review_at, merged_at)
        if first_approval_at and merged_at:
            conversation_summary["approval_to_merge_hours"] = self._hours_between(first_approval_at, merged_at)

        commit_summary = self._summarize_commits(
            pr,
            agent_logins,
            timeline_summary,
            conversation_summary,
        )
        ci_summary = self._collect_ci(repo_full_name, head_sha) if head_sha else {}

        metadata: dict = {
            "review_summary": conversation.get("summary", {}),
            "conversation": conversation,
            "reviews": conversation.get("reviews", []),
            "comments": conversation.get("comments", []),
            "timeline_summary": timeline_summary,
            "timeline_events": timeline.get("events", []),
            "commit_summary": commit_summary,
            "ci_summary": ci_summary,
            "created_at": self._coerce_iso(created_at),
            "merged_at": self._coerce_iso(merged_at),
            "updated_at": self._coerce_iso(updated_at),
        }
        return metadata

    def _fetch_commit(self, repo_full_name: str, sha: str) -> Optional[Commit.Commit]:
        key = (repo_full_name, sha)
        cached = self._commit_cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]
        try:
            repo = self._client.get_repo(repo_full_name)
            commit = repo.get_commit(sha)
        except GithubException:
            commit = None
        self._commit_cache[key] = (now + self._cache_ttl, commit)
        return commit

    def _from_commit(self, repo_full_name: str, sha: str) -> tuple[Optional[str], Optional[str], dict]:
        commit = self._fetch_commit(repo_full_name, sha)
        if not commit:
            return None, None, {"source": "commit", "reason": "not_found"}
        message = commit.commit.message or ""
        trailer_agent = None
        trailer_line = None
        mismatch = False
        for line in message.splitlines():
            match = AGENT_TRAILER_PATTERN.match(line.strip())
            if match:
                trailer_agent = match.group("agent")
                trailer_line = line.strip()
                break
        for line in message.splitlines():
            match = CO_AUTHOR_PATTERN.match(line.strip())
            if match and "copilot" in match.group("author").lower():
                return "github-copilot", None, {"source": "co_author", "value": match.group("author")}
        author_login = getattr(commit.author, "login", "") or ""
        if trailer_agent:
            if author_login and trailer_agent.lower() != author_login.lower():
                mismatch = True
            evidence = {"source": "commit_trailer", "line": trailer_line}
            if author_login:
                evidence["author_login"] = author_login
                if mismatch:
                    evidence["provenance_mismatch"] = True
            return trailer_agent, None, evidence
        if author_login:
            mapped = self._agent_map.get(author_login.lower())
            return mapped or author_login, None, {"source": "commit_author", "value": author_login}
        return None, None, {"source": "commit", "reason": "no_author"}

    def _fetch_pr_labels(self, repo_full_name: str, pr_number: int) -> list[str]:
        key = (repo_full_name, pr_number)
        cached = self._label_cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]
        try:
            repo = self._client.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            labels = [label.name for label in pr.get_labels()]
        except GithubException:
            labels = []
        self._label_cache[key] = (now + self._cache_ttl, labels)
        return labels

    def _from_pr_labels(self, repo_full_name: str, pr_number: int) -> tuple[Optional[str], dict]:
        labels = self._fetch_pr_labels(repo_full_name, pr_number)
        for label in labels:
            lower = label.lower()
            if lower.startswith(self._agent_label_prefix):
                return label.split(":", 1)[-1].strip(), {"source": "label", "label": label}
            mapped = self._agent_map.get(lower)
            if mapped:
                return mapped, {"source": "label_map", "label": label}
        return None, {"source": "label", "labels": labels}

    def _fetch_pr_comments(self, repo_full_name: str, pr_number: int) -> list[str]:
        key = (repo_full_name, pr_number)
        cached = self._comment_cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]
        try:
            repo = self._client.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            comments = [comment.body or "" for comment in pr.get_issue_comments()]
            comments.extend((review.body or "") for review in pr.get_reviews())
        except GithubException:
            comments = []
        self._comment_cache[key] = (now + self._cache_ttl, comments)
        return comments

    def _fetch_review_authors(self, repo_full_name: str, pr_number: int) -> list[str]:
        key = (repo_full_name, pr_number)
        cached = self._reviewer_cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]
        try:
            repo = self._client.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            authors = [review.user.login for review in pr.get_reviews() if review.user and review.user.login]
        except GithubException:
            authors = []
        self._reviewer_cache[key] = (now + self._cache_ttl, authors)
        return authors

    def _fetch_review_events(self, repo_full_name: str, pr_number: int) -> int:
        key = (repo_full_name, pr_number)
        cached = self._review_event_cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]
        try:
            repo = self._client.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            events = pr.get_reviews().totalCount
        except GithubException:
            events = 0
        self._review_event_cache[key] = (now + self._cache_ttl, events)
        return events

    def _get_pull(self, repo_full_name: str, pr_number: int):
        key = (repo_full_name, pr_number)
        cached = self._pull_cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]
        try:
            repo = self._client.get_repo(repo_full_name)
            pull = repo.get_pull(pr_number)
        except GithubException:
            pull = None
        self._pull_cache[key] = (now + self._cache_ttl, pull)
        return pull

    def _collect_ci(self, repo_full_name: str, sha: str) -> dict:
        key = sha
        cached = self._checks_cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]
        summary: dict[str, object] = {
            "run_count": 0,
            "failure_count": 0,
            "latest_status": None,
            "time_to_green_hours": None,
            "failed_checks": [],
            "last_failure_at": None,
            "last_success_at": None,
            "status_contexts": [],
            "check_runs": [],
        }
        try:
            repo = self._client.get_repo(repo_full_name)
            commit = repo.get_commit(sha)
            combined_status = commit.get_combined_status()
            summary["latest_status"] = combined_status.state
            failure_count = 0
            earliest_failure_at = None
            latest_success_at = None
            failed_checks: set[str] = set()
            statuses = list(combined_status.statuses)
            summary["run_count"] = len(statuses)
            for status in statuses:
                updated_at = getattr(status, "updated_at", None)
                if status.state != "success":
                    failure_count += 1
                    if updated_at and (earliest_failure_at is None or updated_at < earliest_failure_at):
                        earliest_failure_at = updated_at
                    if getattr(status, "context", None):
                        failed_checks.add(status.context)
                else:
                    if updated_at and (latest_success_at is None or updated_at > latest_success_at):
                        latest_success_at = updated_at
                summary["status_contexts"].append(
                    {
                        "context": getattr(status, "context", None),
                        "state": status.state,
                        "target_url": getattr(status, "target_url", None),
                        "description": getattr(status, "description", None),
                        "updated_at": self._coerce_iso(updated_at),
                    }
                )
            try:
                check_runs = commit.get_check_runs()
                check_items = list(check_runs)
            except GithubException:
                check_items = []
            summary["run_count"] += len(check_items)
            for run in check_items:
                concluded = getattr(run, "conclusion", None)
                completed_at = getattr(run, "completed_at", None) or getattr(run, "started_at", None)
                if concluded not in ("success", "neutral"):
                    failure_count += 1
                    if completed_at and (earliest_failure_at is None or completed_at < earliest_failure_at):
                        earliest_failure_at = completed_at
                    if getattr(run, "name", None):
                        failed_checks.add(run.name)
                elif concluded == "success":
                    if completed_at and (latest_success_at is None or completed_at > latest_success_at):
                        latest_success_at = completed_at
                summary["check_runs"].append(
                    {
                        "name": getattr(run, "name", None),
                        "status": getattr(run, "status", None),
                        "conclusion": concluded,
                        "started_at": self._coerce_iso(getattr(run, "started_at", None)),
                        "completed_at": self._coerce_iso(getattr(run, "completed_at", None)),
                        "details_url": getattr(run, "html_url", None) or getattr(run, "details_url", None),
                    }
                )
            summary["failure_count"] = failure_count
            summary["failed_checks"] = sorted(check for check in failed_checks if check)
            summary["last_failure_at"] = self._coerce_iso(earliest_failure_at)
            summary["last_success_at"] = self._coerce_iso(latest_success_at)
            if earliest_failure_at and latest_success_at:
                summary["time_to_green_hours"] = self._hours_between(earliest_failure_at, latest_success_at)
        except GithubException:
            pass
        self._checks_cache[key] = (now + self._cache_ttl, summary)
        return summary

    def _build_conversation_snapshot(self, pr, agent_logins: set[str]) -> dict:
        issue_comments = self._safe_paginated(pr.get_issue_comments)
        review_comments = self._safe_paginated(pr.get_review_comments)
        reviews = self._safe_paginated(pr.get_reviews)

        comments_info = self._summarize_comments(issue_comments, review_comments, agent_logins)
        reviews_info = self._summarize_reviews(reviews, agent_logins)
        threads_summary, thread_metrics = self._summarize_threads(comments_info.thread_events)

        classification_counts = self._merge_counts(
            comments_info.classification_counts, reviews_info.classification_counts
        )
        unique_reviewers = comments_info.unique_reviewers | reviews_info.unique_reviewers
        reviewer_identities = self._merge_identities(
            comments_info.reviewer_identities, reviews_info.reviewer_identities
        )

        created_at = getattr(pr, "created_at", None)
        merged_at = getattr(pr, "merged_at", None)

        summary = {
            "review_comment_count": len(comments_info.serialized),
            "unique_reviewers": len(unique_reviewers),
            "review_events": len(reviews_info.entries),
            "agent_comment_mentions": comments_info.agent_mentions,
            "approvals": reviews_info.approvals,
            "requested_changes": reviews_info.requested_changes,
            "comment_threads": thread_metrics["thread_count"],
            "reopened_threads": thread_metrics["reopened_threads"],
            "classification_breakdown": dict(sorted(classification_counts.items(), key=lambda item: item[1], reverse=True)),
            "agent_response_rate": thread_metrics["response_rate"],
            "reviewer_profiles": list(reviewer_identities.values()),
        }

        if thread_metrics["response_latencies"]:
            summary["agent_response_p50_hours"] = statistics.median(thread_metrics["response_latencies"])
            summary["agent_response_p90_hours"] = self._percentile(thread_metrics["response_latencies"], 90)

        if created_at and reviews_info.first_review_time:
            summary["time_to_first_review_hours"] = self._hours_between(created_at, reviews_info.first_review_time)
        if created_at and reviews_info.first_approval_time:
            summary["time_to_first_approval_hours"] = self._hours_between(created_at, reviews_info.first_approval_time)
        if created_at and merged_at:
            summary["time_to_merge_hours"] = self._hours_between(created_at, merged_at)
        if reviews_info.first_review_time:
            summary["first_review_submitted_at"] = self._coerce_iso(reviews_info.first_review_time)
        if reviews_info.first_approval_time:
            summary["first_approval_submitted_at"] = self._coerce_iso(reviews_info.first_approval_time)

        return {
            "comments": comments_info.serialized,
            "reviews": reviews_info.entries,
            "threads": threads_summary,
            "classifications": dict(sorted(classification_counts.items(), key=lambda item: item[1], reverse=True)),
            "summary": summary,
        }

    def _summarize_comments(
        self,
        issue_comments: Sequence,
        review_comments: Sequence,
        agent_logins: set[str],
    ) -> ConversationComments:
        serialized: list[dict] = []
        thread_events: dict[str, list[ThreadEvent]] = defaultdict(list)
        classification_counts: dict[str, int] = defaultdict(int)
        unique_reviewers: set[str] = set()
        agent_mentions = 0
        reviewer_identities: dict[str, dict] = {}

        for comment in issue_comments:
            entry, thread_key, event, classification = self._serialize_comment(
                comment, "issue_comment", agent_logins, len(serialized)
            )
            serialized.append(entry)
            thread_events[thread_key].append(event)
            classification_counts[classification] += 1
            if event.author and not event.is_agent:
                unique_reviewers.add(event.author)
                reviewer_identities.setdefault(event.author, self._extract_user_profile(comment, event.author))
            if AGENT_TRAILER_PATTERN.search(entry["body"]):
                agent_mentions += 1

        for comment in review_comments:
            entry, thread_key, event, classification = self._serialize_comment(
                comment, "review_comment", agent_logins, len(serialized)
            )
            serialized.append(entry)
            thread_events[thread_key].append(event)
            classification_counts[classification] += 1
            if event.author and not event.is_agent:
                unique_reviewers.add(event.author)
                reviewer_identities.setdefault(event.author, self._extract_user_profile(comment, event.author))
            if AGENT_TRAILER_PATTERN.search(entry["body"]):
                agent_mentions += 1

        normalized_threads = {key: events[:] for key, events in thread_events.items()}
        return ConversationComments(
            serialized=serialized,
            thread_events=normalized_threads,
            classification_counts=dict(classification_counts),
            unique_reviewers=unique_reviewers,
            agent_mentions=agent_mentions,
            reviewer_identities=reviewer_identities,
        )

    def _summarize_reviews(
        self,
        reviews: Sequence,
        agent_logins: set[str],
    ) -> ConversationReviews:
        entries: list[dict] = []
        classification_counts: dict[str, int] = defaultdict(int)
        unique_reviewers: set[str] = set()
        approvals = 0
        requested_changes = 0
        first_review_time: datetime | None = None
        first_approval_time: datetime | None = None
        reviewer_identities: dict[str, dict] = {}

        for review in reviews:
            submitted_at = getattr(review, "submitted_at", None)
            author_login = getattr(getattr(review, "user", None), "login", None)
            classification = self._classify_review(review.state, review.body or "")
            entries.append(
                {
                    "author": author_login,
                    "state": review.state,
                    "submitted_at": self._coerce_iso(submitted_at),
                    "body": review.body or "",
                    "classification": classification,
                }
            )
            classification_counts[classification] += 1
            if author_login and not self._is_agent_login(author_login, agent_logins):
                unique_reviewers.add(author_login)
                reviewer_identities.setdefault(author_login, self._extract_user_profile(review, author_login))
            if submitted_at and (first_review_time is None or submitted_at < first_review_time):
                first_review_time = submitted_at
            if review.state == "APPROVED":
                approvals += 1
                if submitted_at and (first_approval_time is None or submitted_at < first_approval_time):
                    first_approval_time = submitted_at
            if review.state == "CHANGES_REQUESTED":
                requested_changes += 1

        return ConversationReviews(
            entries=entries,
            classification_counts=dict(classification_counts),
            unique_reviewers=unique_reviewers,
            approvals=approvals,
            requested_changes=requested_changes,
            first_review_time=first_review_time,
            first_approval_time=first_approval_time,
            reviewer_identities=reviewer_identities,
        )

    def _summarize_threads(
        self,
        thread_events: dict[str, list[ThreadEvent]],
    ) -> tuple[list[dict], dict]:
        threads_summary: list[dict] = []
        response_latencies: list[float] = []
        responded_threads = 0
        reopened_threads = 0
        for thread_id, events in thread_events.items():
            sorted_events = self._sort_events(events)
            participants = sorted({event.author for event in sorted_events if event.author})
            first_reviewer_event = next((event for event in sorted_events if not event.is_agent), None)
            agent_response_hours = None
            first_agent_event: ThreadEvent | None = None
            if first_reviewer_event and first_reviewer_event.created_at:
                for event in sorted_events:
                    if not event.is_agent or not event.created_at:
                        continue
                    if event.created_at >= first_reviewer_event.created_at:
                        agent_response_hours = self._hours_between(first_reviewer_event.created_at, event.created_at)
                        if agent_response_hours is not None:
                            response_latencies.append(agent_response_hours)
                            responded_threads += 1
                            first_agent_event = event
                        break
            reopened = False
            if first_agent_event and first_agent_event.created_at:
                for event in sorted_events:
                    if event is first_agent_event or event.is_agent or not event.created_at:
                        continue
                    if event.created_at > first_agent_event.created_at:
                        reopened = True
                        reopened_threads += 1
                        break
            threads_summary.append(
                {
                    "thread_id": thread_id,
                    "comment_count": len(sorted_events),
                    "participants": participants,
                    "reopened": reopened,
                    "agent_response_hours": agent_response_hours,
                    "first_comment_at": self._coerce_iso(sorted_events[0].created_at) if sorted_events else None,
                    "last_comment_at": self._coerce_iso(sorted_events[-1].created_at) if sorted_events else None,
                }
            )

        thread_count = len(thread_events)
        metrics = {
            "thread_count": thread_count,
            "reopened_threads": reopened_threads,
            "response_rate": (responded_threads / thread_count) if thread_count else 0.0,
            "response_latencies": response_latencies,
        }
        return threads_summary, metrics

    def _serialize_comment(
        self,
        comment,
        comment_type: str,
        agent_logins: set[str],
        index: int,
    ) -> tuple[dict, str, ThreadEvent, str]:
        body = comment.body or ""
        created_at = getattr(comment, "created_at", None)
        updated_at = getattr(comment, "updated_at", None)
        author_login = getattr(getattr(comment, "user", None), "login", None)
        classification = self._classify_comment(body)
        serialized = {
            "id": getattr(comment, "id", None),
            "author": author_login,
            "body": body,
            "type": comment_type,
            "classification": classification,
            "created_at": self._coerce_iso(created_at),
            "updated_at": self._coerce_iso(updated_at),
        }
        if comment_type == "review_comment":
            serialized["in_reply_to_id"] = getattr(comment, "in_reply_to_id", None)
        thread_id = getattr(comment, "in_reply_to_id", None) or getattr(comment, "id", None)
        thread_key = str(thread_id) if thread_id is not None else f"{comment_type}-{index}"
        event = ThreadEvent(
            author=author_login,
            created_at=created_at,
            is_agent=self._is_agent_login(author_login, agent_logins),
        )
        return serialized, thread_key, event, classification

    @staticmethod
    def _merge_counts(primary: dict[str, int], secondary: dict[str, int]) -> dict[str, int]:
        totals: dict[str, int] = defaultdict(int)
        for mapping in (primary, secondary):
            for label, count in mapping.items():
                totals[label] += count
        return dict(totals)

    @staticmethod
    def _safe_paginated(fetcher: Callable[[], Iterable]) -> list:
        try:
            return list(fetcher())
        except GithubException:
            return []

    @staticmethod
    def _sort_events(events: Sequence[ThreadEvent]) -> list[ThreadEvent]:
        epoch = datetime.fromtimestamp(0, tz=timezone.utc)
        return sorted(events, key=lambda event: event.created_at or epoch)

    @staticmethod
    def _merge_identities(primary: dict[str, dict], secondary: dict[str, dict]) -> dict[str, dict]:
        merged = {**primary}
        for login, profile in secondary.items():
            merged.setdefault(login, profile)
        return merged

    def _extract_user_profile(self, source_obj, login: str) -> dict:
        user = getattr(source_obj, "user", None)
        profile = {"login": login}
        if not user:
            return profile
        for attr in ("name", "type", "company", "email", "location"):
            profile[attr] = getattr(user, attr, None)
        association = getattr(source_obj, "author_association", None)
        profile["association"] = association
        return profile

    @staticmethod
    def _parse_iso(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def _collect_timeline(self, repo_full_name: str, pr_number: int, pr=None) -> dict:
        key = (repo_full_name, pr_number)
        cached = self._timeline_cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            return cached[1]

        data = {
            "events": [],
            "summary": {
                "force_pushes": 0,
                "reopens": 0,
                "merge_events": 0,
                "review_requests": 0,
                "review_dismissals": 0,
                "last_force_push_at": None,
                "last_reopen_at": None,
                "last_merge_at": None,
                "last_review_request_at": None,
                "ready_for_review_at": None,
                "converted_to_draft_at": None,
            },
        }
        timeline_items: list = []
        try:
            target_pr = pr or self._get_pull(repo_full_name, pr_number)
            if not target_pr:
                self._timeline_cache[key] = (now + self._cache_ttl, data)
                return data
            get_timeline = getattr(target_pr, "get_timeline", None)
            if callable(get_timeline):
                try:
                    timeline_items = list(get_timeline())
                except GithubException:
                    timeline_items = []
            else:
                try:
                    timeline_items = list(target_pr.get_issue_events())
                except GithubException:
                    timeline_items = []
        except GithubException:
            timeline_items = []

        events: list[dict] = []
        summary_counts: dict[str, int] = defaultdict(int)
        for item in timeline_items:
            event_type = getattr(item, "event", None)
            if not event_type:
                continue
            if event_type not in {
                "head_ref_force_pushed",
                "reopened",
                "closed",
                "merged",
                "review_requested",
                "review_request_removed",
                "review_dismissed",
                "ready_for_review",
                "converted_to_draft",
            }:
                continue
            summary_counts[event_type] += 1
            created_at = getattr(item, "created_at", None)
            created_iso = self._coerce_iso(created_at)
            events.append(
                {
                    "type": event_type,
                    "actor": getattr(getattr(item, "actor", None), "login", None),
                    "created_at": created_iso,
                    "commit_id": getattr(item, "head_sha", None) or getattr(item, "commit_id", None),
                }
            )
            if event_type == "head_ref_force_pushed":
                data["summary"]["last_force_push_at"] = created_iso
            elif event_type == "reopened":
                data["summary"]["last_reopen_at"] = created_iso
            elif event_type == "merged":
                data["summary"]["last_merge_at"] = created_iso
            elif event_type == "review_requested":
                data["summary"]["last_review_request_at"] = created_iso
            elif event_type == "ready_for_review" and data["summary"]["ready_for_review_at"] is None:
                data["summary"]["ready_for_review_at"] = created_iso
            elif event_type == "converted_to_draft":
                data["summary"]["converted_to_draft_at"] = created_iso

        data["events"] = events
        data["summary"] = {
            "force_pushes": summary_counts.get("head_ref_force_pushed", 0),
            "reopens": summary_counts.get("reopened", 0),
            "merge_events": summary_counts.get("merged", 0),
            "review_requests": summary_counts.get("review_requested", 0),
            "review_dismissals": summary_counts.get("review_dismissed", 0),
            "last_force_push_at": data["summary"]["last_force_push_at"],
            "last_reopen_at": data["summary"]["last_reopen_at"],
            "last_merge_at": data["summary"]["last_merge_at"],
            "last_review_request_at": data["summary"]["last_review_request_at"],
            "ready_for_review_at": data["summary"]["ready_for_review_at"],
            "converted_to_draft_at": data["summary"]["converted_to_draft_at"],
        }
        self._timeline_cache[key] = (now + self._cache_ttl, data)
        return data

    def _summarize_commits(
        self,
        pr,
        agent_logins: set[str],
        timeline_summary: dict,
        review_summary: dict,
    ) -> dict:
        try:
            commits = list(pr.get_commits())
        except GithubException:
            commits = []

        commit_entries: list[dict] = []
        unique_authors: set[str] = set()
        agent_commits = 0
        human_commits = 0
        revert_commits = 0
        commit_moments: list[dict] = []
        human_followups = 0
        human_followups_fast = 0
        rewrite_loops = 0

        for commit in commits:
            author_login = getattr(commit.author, "login", None)
            commit_date = getattr(getattr(commit.commit, "author", None), "date", None)
            message = (commit.commit.message or "").strip()
            headline = message.splitlines()[0] if message else ""
            entry = {
                "sha": getattr(commit, "sha", None),
                "author": author_login,
                "authored_at": self._coerce_iso(commit_date),
                "message_headline": headline[:120],
            }
            commit_entries.append(entry)
            if author_login:
                unique_authors.add(author_login)
            is_agent = self._is_agent_login(author_login, agent_logins)
            if is_agent:
                agent_commits += 1
            else:
                human_commits += 1
            if message.lower().startswith("revert"):
                revert_commits += 1
            commit_moments.append({"author": author_login, "created_at": commit_date, "is_agent": is_agent})

        sorted_moments = sorted(
            commit_moments,
            key=lambda meta: meta["created_at"] or datetime.fromtimestamp(0, tz=timezone.utc),
        )
        for idx, current in enumerate(sorted_moments[:-1]):
            nxt = sorted_moments[idx + 1]
            if current["is_agent"] and not nxt["is_agent"]:
                delta = self._hours_between(current["created_at"], nxt["created_at"])
                if delta is not None:
                    human_followups += 1
                    if delta <= 1:
                        human_followups_fast += 1
                    if delta <= 48:
                        rewrite_loops += 1
        intervals: list[float] = []
        for idx, current in enumerate(sorted_moments[:-1]):
            nxt = sorted_moments[idx + 1]
            delta = self._hours_between(current["created_at"], nxt["created_at"])
            if delta is not None:
                intervals.append(delta)

        total_commits = len(commit_entries)
        summary = {
            "total_commits": total_commits,
            "agent_commits": agent_commits,
            "human_commits": human_commits,
            "unique_authors": len(unique_authors),
            "revert_commits": revert_commits,
            "force_push_events": timeline_summary.get("force_pushes", 0),
            "human_followup_commits": human_followups,
            "human_followup_commits_fast": human_followups_fast,
            "rewrite_loops": rewrite_loops,
            "agent_commit_ratio": (agent_commits / total_commits) if total_commits else 0.0,
            "commits": commit_entries,
        }

        if intervals:
            summary["avg_time_between_commits_hours"] = sum(intervals) / len(intervals)
            summary["max_time_between_commits_hours"] = max(intervals)
        commit_times = [meta["created_at"] for meta in sorted_moments if meta["created_at"]]
        if commit_times:
            summary["lead_time_hours"] = self._hours_between(min(commit_times), max(commit_times))
        last_force_push_at = timeline_summary.get("last_force_push_at")
        first_approval_iso = review_summary.get("first_approval_submitted_at")
        if last_force_push_at and first_approval_iso:
            force_push_dt = self._parse_iso(last_force_push_at)
            approval_dt = self._parse_iso(first_approval_iso)
            if force_push_dt and approval_dt and force_push_dt > approval_dt:
                summary["force_push_after_approval"] = True

        return summary

    @staticmethod
    def _classify_comment(body: str) -> str:
        text = (body or "").lower()
        if not text:
            return "neutral"
        if any(keyword in text for keyword in ("security", "vulnerability", "xss", "sql injection", "leak")):
            return "security"
        if any(keyword in text for keyword in ("nit", "nitpick", "style", "typo")):
            return "nit"
        if any(keyword in text for keyword in ("?", "clarify", "explain", "what if", "could you")):
            return "question"
        if any(keyword in text for keyword in ("thanks", "great", "nice work", "awesome", "lgtm")):
            return "praise"
        if any(keyword in text for keyword in ("bug", "broken", "fix", "incorrect", "fail")):
            return "bug"
        return "general"

    @staticmethod
    def _classify_review(state: str, body: str) -> str:
        text = (body or "").lower()
        upper_state = (state or "").upper()
        if upper_state == "APPROVED":
            return "approval"
        if upper_state == "CHANGES_REQUESTED":
            return "blocking"
        if "nit" in text:
            return "nit"
        if "security" in text or "vulnerability" in text:
            return "security"
        if "?" in text or "clarify" in text:
            return "question"
        return "general"

    def _is_agent_login(self, login: str | None, agent_logins: set[str]) -> bool:
        if not login:
            return False
        lower = login.lower()
        if lower in agent_logins:
            return True
        mapped = self._agent_map.get(lower)
        if mapped:
            return True
        if lower.endswith("-bot"):
            return True
        return any(keyword in lower for keyword in ("copilot", "claude", "gemini", "gpt", "bard", "llama"))

    @staticmethod
    def _coerce_iso(value) -> str | None:
        if not value:
            return None
        if isinstance(value, datetime):
            dt = value
        else:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _hours_between(start, end) -> float | None:
        if not start or not end:
            return None
        if isinstance(start, datetime):
            start_dt = start
        else:
            return None
        if isinstance(end, datetime):
            end_dt = end
        else:
            return None
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=timezone.utc)
        delta_seconds = (end_dt - start_dt).total_seconds()
        if delta_seconds < 0:
            return None
        return delta_seconds / 3600

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        if not values:
            return 0.0
        percentile = max(0.0, min(percentile, 100.0))
        sorted_values = sorted(values)
        if len(sorted_values) == 1:
            return sorted_values[0]
        rank = (len(sorted_values) - 1) * (percentile / 100.0)
        lower_index = int(math.floor(rank))
        upper_index = int(math.ceil(rank))
        lower_value = sorted_values[lower_index]
        upper_value = sorted_values[upper_index]
        if lower_index == upper_index:
            return lower_value
        fraction = rank - lower_index
        return lower_value + (upper_value - lower_value) * fraction

    def _from_pr_discussion(self, repo_full_name: str, pr_number: int) -> tuple[Optional[str], dict]:
        for body in self._fetch_pr_comments(repo_full_name, pr_number):
            for line in body.splitlines():
                match = AGENT_TRAILER_PATTERN.match(line.strip())
                if match:
                    return match.group("agent"), {"source": "comment", "line": line.strip()}
        for author in self._fetch_review_authors(repo_full_name, pr_number):
            lower = author.lower()
            if "copilot" in lower:
                return "github-copilot", {"source": "reviewer", "value": author}
            mapped = self._agent_map.get(lower)
            if mapped:
                return mapped, {"source": "reviewer_map", "value": author}
            if any(key in lower for key in ("claude", "gemini", "gpt", "bard")):
                return lower, {"source": "reviewer_heuristic", "value": author}
            if lower.endswith("-bot"):
                return lower, {"source": "reviewer_bot", "value": author}
        return None, {"source": "discussion", "reason": "no_match"}

    def _from_pr_body(self, repo_full_name: str, pr_number: int) -> tuple[Optional[str], dict]:
        try:
            repo = self._client.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            body = pr.body or ""
        except GithubException:
            return None, {"source": "body", "reason": "error"}
        for line in body.splitlines():
            match = AGENT_TRAILER_PATTERN.match(line.strip())
            if match:
                return match.group("agent"), {"source": "body", "line": line.strip()}
        lower_body = body.lower()
        for key, mapped in self._agent_map.items():
            if key in lower_body:
                return mapped, {"source": "body_map", "value": key}
        return None, {"source": "body", "reason": "no_match"}
