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
    ) -> None:
        self._agent_label_prefix = agent_label_prefix.lower()
        auth = Token(token)
        if base_url:
            self._client = Github(auth=auth, base_url=base_url.rstrip("/"))
        else:
            self._client = Github(auth=auth)
        self._cache_ttl = max(cache_ttl_seconds, 30)
        self._commit_cache: dict[tuple[str, str], tuple[float, Optional[Commit.Commit]]] = {}
        self._label_cache: dict[tuple[str, int], tuple[float, list[str]]] = {}
        self._comment_cache: dict[tuple[str, int], tuple[float, list[str]]] = {}
        self._reviewer_cache: dict[tuple[str, int], tuple[float, list[str]]] = {}

    def resolve_agent(
        self,
        repo_full_name: str,
        pr_number: str | None,
        commit_sha: str | None,
    ) -> tuple[Optional[str], Optional[str]]:
        agent_id: Optional[str] = None
        session_id: Optional[str] = None

        if commit_sha:
            agent_id, session_id = self._from_commit(repo_full_name, commit_sha)
        if not agent_id and pr_number:
            agent_id = self._from_pr_labels(repo_full_name, int(pr_number))
        if not agent_id and pr_number:
            agent_id = self._from_pr_discussion(repo_full_name, int(pr_number))
        return agent_id, session_id

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

    def _from_commit(self, repo_full_name: str, sha: str) -> tuple[Optional[str], Optional[str]]:
        commit = self._fetch_commit(repo_full_name, sha)
        if not commit:
            return None, None
        message = commit.commit.message or ""
        for line in message.splitlines():
            match = AGENT_TRAILER_PATTERN.match(line.strip())
            if match:
                return match.group("agent"), None
        for line in message.splitlines():
            match = CO_AUTHOR_PATTERN.match(line.strip())
            if match and "copilot" in match.group("author").lower():
                return "github-copilot", None
        author_login = getattr(commit.author, "login", "") or ""
        if author_login:
            return author_login, None
        return None, None

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

    def _from_pr_labels(self, repo_full_name: str, pr_number: int) -> Optional[str]:
        for label in self._fetch_pr_labels(repo_full_name, pr_number):
            lower = label.lower()
            if lower.startswith(self._agent_label_prefix):
                return label.split(":", 1)[-1].strip()
        return None

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

    def _from_pr_discussion(self, repo_full_name: str, pr_number: int) -> Optional[str]:
        for body in self._fetch_pr_comments(repo_full_name, pr_number):
            for line in body.splitlines():
                match = AGENT_TRAILER_PATTERN.match(line.strip())
                if match:
                    return match.group("agent")
        for author in self._fetch_review_authors(repo_full_name, pr_number):
            lower = author.lower()
            if "copilot" in lower:
                return "github-copilot"
            if any(key in lower for key in ("claude", "gemini", "gpt", "bard")):
                return lower
            if lower.endswith("-bot"):
                return lower
        return None
