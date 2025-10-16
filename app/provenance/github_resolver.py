"""GitHub-backed provenance resolution."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Optional

from github import Github, GithubException, Commit

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
    ) -> None:
        self._agent_label_prefix = agent_label_prefix.lower()
        if base_url:
            self._client = Github(login_or_token=token, base_url=base_url.rstrip("/"))
        else:
            self._client = Github(login_or_token=token)

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
        return agent_id, session_id

    @lru_cache(maxsize=256)
    def _fetch_commit(self, repo_full_name: str, sha: str) -> Optional[Commit.Commit]:
        try:
            repo = self._client.get_repo(repo_full_name)
            return repo.get_commit(sha)
        except GithubException:
            return None

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

    @lru_cache(maxsize=256)
    def _fetch_pr_labels(self, repo_full_name: str, pr_number: int) -> list[str]:
        try:
            repo = self._client.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            return [label.name for label in pr.get_labels()]
        except GithubException:
            return []

    def _from_pr_labels(self, repo_full_name: str, pr_number: int) -> Optional[str]:
        for label in self._fetch_pr_labels(repo_full_name, pr_number):
            lower = label.lower()
            if lower.startswith(self._agent_label_prefix):
                return label.split(":", 1)[-1].strip()
        return None
