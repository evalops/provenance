from __future__ import annotations

from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

from app.provenance.github_resolver import GitHubProvenanceResolver


class StubCommit:
    def __init__(self, message: str, author_login: str | None = None):
        self.commit = SimpleNamespace(message=message)
        self.author = SimpleNamespace(login=author_login) if author_login else None


def test_resolver_extracts_agent_from_commit_trailer(monkeypatch):
    resolver = GitHubProvenanceResolver(token="token")
    monkeypatch.setattr(
        GitHubProvenanceResolver,
        "_fetch_commit",
        lambda self, repo, sha: StubCommit("Fix bug\nAgent-ID: claude-3-opus"),
    )
    agent, session, evidence = resolver.resolve_agent("acme/repo", "42", "abc123")
    assert agent == "claude-3-opus"
    assert session is None
    assert evidence["agent_id"] == "claude-3-opus"


def test_resolver_uses_coauthor(monkeypatch):
    resolver = GitHubProvenanceResolver(token="token")
    message = "Refactor\nCo-authored-by: GitHub Copilot <copilot@example.com>"
    monkeypatch.setattr(GitHubProvenanceResolver, "_fetch_commit", lambda self, repo, sha: StubCommit(message))
    agent, _, evidence = resolver.resolve_agent("acme/repo", None, "def456")
    assert agent == "github-copilot"
    assert evidence["agent_id"] == "github-copilot"


def test_resolver_falls_back_to_pr_labels(monkeypatch):
    resolver = GitHubProvenanceResolver(token="token", agent_label_prefix="agent:")
    monkeypatch.setattr(GitHubProvenanceResolver, "_fetch_commit", lambda self, repo, sha: None)
    monkeypatch.setattr(GitHubProvenanceResolver, "_fetch_pr_labels", lambda self, repo, pr: ["Agent: gemini-pro"])
    agent, _, evidence = resolver.resolve_agent("acme/repo", "77", None)
    assert agent == "gemini-pro"
    assert evidence["agent_id"] == "gemini-pro"


def test_resolver_uses_pr_comments(monkeypatch):
    resolver = GitHubProvenanceResolver(token="token")
    monkeypatch.setattr(GitHubProvenanceResolver, "_fetch_commit", lambda self, repo, sha: None)
    monkeypatch.setattr(GitHubProvenanceResolver, "_fetch_pr_labels", lambda self, repo, pr: [])
    monkeypatch.setattr(
        GitHubProvenanceResolver,
        "_fetch_pr_comments",
        lambda self, repo, pr: ["LGTM\nAgent-ID: gemma-7b"],
    )
    agent, _, evidence = resolver.resolve_agent("acme/repo", "77", None)
    assert agent == "gemma-7b"
    assert evidence["agent_id"] == "gemma-7b"


def test_review_stats(monkeypatch):
    resolver = GitHubProvenanceResolver(token="token")
    now = datetime.now(timezone.utc)

    class StubComment:
        def __init__(self, *, body: str, author: str, created_at: datetime, comment_id: int, in_reply_to_id: int | None = None):
            self.body = body
            self.user = SimpleNamespace(login=author)
            self.created_at = created_at
            self.updated_at = created_at
            self.id = comment_id
            self.in_reply_to_id = in_reply_to_id

    class StubReview:
        def __init__(self, *, state: str, body: str, author: str, submitted_at: datetime):
            self.state = state
            self.body = body
            self.user = SimpleNamespace(login=author)
            self.submitted_at = submitted_at

    class StubPull:
        def __init__(self):
            self.created_at = now - timedelta(hours=4)
            self.merged_at = now
            self.updated_at = now

        def get_issue_comments(self):
            return [
                StubComment(body="Agent-ID: claude", author="reviewer-a", created_at=now - timedelta(hours=3), comment_id=1),
            ]

        def get_review_comments(self):
            return [
                StubComment(body="please fix", author="reviewer-b", created_at=now - timedelta(hours=2), comment_id=2),
                StubComment(body="updated as requested", author="claude-bot", created_at=now - timedelta(hours=1), comment_id=3, in_reply_to_id=2),
                StubComment(body="looks good now", author="reviewer-b", created_at=now - timedelta(minutes=30), comment_id=4, in_reply_to_id=2),
            ]

        def get_reviews(self):
            return [
                StubReview(state="COMMENTED", body="Initial thoughts", author="reviewer-a", submitted_at=now - timedelta(hours=3, minutes=30)),
                StubReview(state="APPROVED", body="Ship it", author="reviewer-b", submitted_at=now - timedelta(minutes=20)),
            ]

        def get_timeline(self):
            return []

    monkeypatch.setattr(GitHubProvenanceResolver, "_get_pull", lambda self, repo, pr: StubPull())
    stats = resolver.review_stats("acme/repo", 99)
    assert stats["review_comment_count"] == 4
    assert stats["unique_reviewers"] == 2
    assert stats["review_events"] == 2
    assert stats["agent_comment_mentions"] == 1
    assert stats["reopened_threads"] == 1
    assert stats["approvals"] == 1
    assert stats["comment_threads"] == 2
    assert stats["bot_review_events"] == 0
    assert stats["bot_block_events"] == 0
    assert stats.get("bot_block_overrides", 0) == 0
    assert stats.get("bot_block_resolved", 0) == 0
    assert stats.get("bot_reviewer_count", 0) == 0
