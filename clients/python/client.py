from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable

import httpx


@dataclass
class AnalysisRequest:
    """Convenience wrapper for POST /analysis payloads."""

    repo: str
    pr_number: str
    base_sha: str
    head_sha: str
    branch: str | None = None
    provenance_data: Dict[str, Any] = field(default_factory=lambda: {"changed_lines": []})


class ProvenanceClient:
    """Lightweight synchronous client for the Provenance API."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        headers: Dict[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        normalized_base = base_url.rstrip("/") + "/"
        self._client = httpx.Client(
            base_url=normalized_base,
            timeout=timeout,
            headers=headers,
            transport=transport,
        )

    def __enter__(self) -> "ProvenanceClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def submit_analysis(self, request: AnalysisRequest) -> dict:
        response = self._client.post("analysis", json=asdict(request))
        response.raise_for_status()
        return response.json()

    def get_analysis_status(self, analysis_id: str) -> dict:
        response = self._client.get(f"analysis/{analysis_id}")
        response.raise_for_status()
        return response.json()

    def get_analysis_decision(self, analysis_id: str) -> dict:
        response = self._client.get(f"analysis/{analysis_id}/decision")
        response.raise_for_status()
        return response.json()

    def get_analytics_summary(
        self,
        metric: str,
        *,
        time_window: str = "7d",
        group_by: str = "agent_id",
        category: str | None = None,
        agent_id: str | None = None,
    ) -> dict:
        params = {
            "metric": metric,
            "time_window": time_window,
            "group_by": group_by,
        }
        if category:
            params["category"] = category
        if agent_id:
            params["agent_id"] = agent_id
        response = self._client.get("analytics/summary", params=params)
        response.raise_for_status()
        return response.json()

    def get_agent_behavior(self, *, time_window: str = "7d", agent_id: str | None = None, top_categories: int = 3) -> dict:
        params = {"time_window": time_window, "top_categories": top_categories}
        if agent_id:
            params["agent_id"] = agent_id
        response = self._client.get("analytics/agents/behavior", params=params)
        response.raise_for_status()
        return response.json()

    def healthcheck(self) -> dict:
        response = self._client.get("healthz")
        response.raise_for_status()
        return response.json()
