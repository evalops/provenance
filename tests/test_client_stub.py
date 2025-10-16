from __future__ import annotations

import json

import httpx

from clients.python import AnalysisRequest, ProvenanceClient


def test_client_submit_analysis_payload():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["json"] = json.loads(request.content.decode())
        return httpx.Response(202, json={"analysis_id": "an_1", "status": "received"})

    transport = httpx.MockTransport(handler)
    with ProvenanceClient("http://example.com/v1", transport=transport) as client:
        request = AnalysisRequest(
            repo="acme/repo",
            pr_number="42",
            base_sha="base",
            head_sha="head",
            provenance_data={"changed_lines": []},
        )
        response = client.submit_analysis(request)

    assert response["analysis_id"] == "an_1"
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/analysis")
    assert captured["json"]["repo"] == "acme/repo"


def test_client_summary_queries():
    params_captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        params_captured.update(request.url.params)
        return httpx.Response(200, json={"result": {"data": []}})

    transport = httpx.MockTransport(handler)
    with ProvenanceClient("http://example.com/v1", transport=transport) as client:
        client.get_analytics_summary("risk_rate", time_window="3d", category="sqli", agent_id="claude")

    assert params_captured["metric"] == "risk_rate"
    assert params_captured["time_window"] == "3d"
    assert params_captured["category"] == "sqli"
    assert params_captured["agent_id"] == "claude"
