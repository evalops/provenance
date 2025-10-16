from __future__ import annotations

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
    agent, session = resolver.resolve_agent("acme/repo", "42", "abc123")
    assert agent == "claude-3-opus"
    assert session is None


def test_resolver_uses_coauthor(monkeypatch):
    resolver = GitHubProvenanceResolver(token="token")
    message = "Refactor\nCo-authored-by: GitHub Copilot <copilot@example.com>"
    monkeypatch.setattr(GitHubProvenanceResolver, "_fetch_commit", lambda self, repo, sha: StubCommit(message))
    agent, _ = resolver.resolve_agent("acme/repo", None, "def456")
    assert agent == "github-copilot"


def test_resolver_falls_back_to_pr_labels(monkeypatch):
    resolver = GitHubProvenanceResolver(token="token", agent_label_prefix="agent:")
    monkeypatch.setattr(GitHubProvenanceResolver, "_fetch_commit", lambda self, repo, sha: None)
    monkeypatch.setattr(GitHubProvenanceResolver, "_fetch_pr_labels", lambda self, repo, pr: ["Agent: gemini-pro"])
    agent, _ = resolver.resolve_agent("acme/repo", "77", None)
    assert agent == "gemini-pro"
