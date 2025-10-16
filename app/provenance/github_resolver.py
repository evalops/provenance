"""GitHub-backed provenance resolution."""

from __future__ import annotations

import re
import time
from typing import Optional

from github import Github, GithubException, Commit
from github.Auth import Token

AGENT_TRAILER_PATTERN = re.compile(r"^Agent-ID:\s*(?P<agent>[^\s]+)", re.IGNORECASE)
CO_AUTHOR_PATTERN = re.compile(r"Co-authored-by:\s*(?P<author>.+)", re.IGNORECASE)


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

    def resolve_agent(
        self,
        repo_full_name: str,
        pr_number: str | None,
        commit_sha: str | None,
    ) -> tuple[Optional[str], Optional[str], dict]:
        agent_id: Optional[str] = None
        session_id: Optional[str] = None
        evidence: dict = {}

        if commit_sha:
            agent_id, session_id, commit_evidence = self._from_commit(repo_full_name, commit_sha)
            evidence.setdefault("sources", []).append(commit_evidence)
        if not agent_id and pr_number:
            label_agent, label_evidence = self._from_pr_labels(repo_full_name, int(pr_number))
            if label_agent:
                agent_id = label_agent
            evidence.setdefault("sources", []).append(label_evidence)
        if not agent_id and pr_number:
            discussion_agent, discussion_evidence = self._from_pr_discussion(repo_full_name, int(pr_number))
            if discussion_agent:
                agent_id = discussion_agent
            evidence.setdefault("sources", []).append(discussion_evidence)
        if not agent_id and pr_number:
            body_agent, body_evidence = self._from_pr_body(repo_full_name, int(pr_number))
            if body_agent:
                agent_id = body_agent
            evidence.setdefault("sources", []).append(body_evidence)
        evidence["agent_id"] = agent_id
        return agent_id, session_id, evidence

    def review_stats(self, repo_full_name: str, pr_number: int) -> dict[str, int] | None:
        comments = self._fetch_pr_comments(repo_full_name, pr_number)
        reviewers = self._fetch_review_authors(repo_full_name, pr_number)
        review_events = self._fetch_review_events(repo_full_name, pr_number)
        if not comments and not reviewers and not review_events:
            return None
        agent_mentions = sum(1 for body in comments for line in body.splitlines() if AGENT_TRAILER_PATTERN.match(line.strip()))
        return {
            "review_comment_count": len(comments),
            "unique_reviewers": len(set(reviewers)),
            "review_events": review_events,
            "agent_comment_mentions": agent_mentions,
        }

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
        for line in message.splitlines():
            match = AGENT_TRAILER_PATTERN.match(line.strip())
            if match:
                return match.group("agent"), None, {"source": "commit_trailer", "line": line.strip()}
        for line in message.splitlines():
            match = CO_AUTHOR_PATTERN.match(line.strip())
            if match and "copilot" in match.group("author").lower():
                return "github-copilot", None, {"source": "co_author", "value": match.group("author")}
        author_login = getattr(commit.author, "login", "") or ""
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
