from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict

import httpx

from .client import AnalysisRequest


class AsyncProvenanceClient:
    """Async variant of the Provenance API client."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        headers: Dict[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        normalized_base = base_url.rstrip("/") + "/"
        self._client = httpx.AsyncClient(
            base_url=normalized_base,
            timeout=timeout,
            headers=headers,
            transport=transport,
        )

    async def __aenter__(self) -> "AsyncProvenanceClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def submit_analysis(self, request: AnalysisRequest) -> dict:
        response = await self._client.post("analysis", json=asdict(request))
        response.raise_for_status()
        return response.json()

    async def get_analysis_status(self, analysis_id: str) -> dict:
        response = await self._client.get(f"analysis/{analysis_id}")
        response.raise_for_status()
        return response.json()

    async def get_analysis_decision(self, analysis_id: str) -> dict:
        response = await self._client.get(f"analysis/{analysis_id}/decision")
        response.raise_for_status()
        return response.json()

    async def get_analytics_summary(
        self,
        metric: str,
        *,
        time_window: str = "7d",
        group_by: str = "agent_id",
        category: str | None = None,
        agent_id: str | None = None,
    ) -> dict:
        params: Dict[str, Any] = {
            "metric": metric,
            "time_window": time_window,
            "group_by": group_by,
        }
        if category:
            params["category"] = category
        if agent_id:
            params["agent_id"] = agent_id
        response = await self._client.get("analytics/summary", params=params)
        response.raise_for_status()
        return response.json()

    async def get_agent_behavior(self, *, time_window: str = "7d", agent_id: str | None = None, top_categories: int = 3) -> dict:
        params: Dict[str, Any] = {"time_window": time_window, "top_categories": top_categories}
        if agent_id:
            params["agent_id"] = agent_id
        response = await self._client.get("analytics/agents/behavior", params=params)
        response.raise_for_status()
        return response.json()

    async def healthcheck(self) -> dict:
        response = await self._client.get("healthz")
        response.raise_for_status()
        return response.json()
