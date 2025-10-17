from __future__ import annotations

from datetime import datetime, timezone

import fakeredis
from fastapi.testclient import TestClient
from app.dependencies import (
    get_analysis_service,
    get_analytics_service,
    get_detection_service,
    get_event_sink,
    get_governance_service,
    get_store,
)
from app.main import create_app
from app.repositories.redis_store import RedisWarehouse
from app.services.analytics import AnalyticsService
from app.services.analysis import AnalysisService
from app.services.detection import DetectionService
from app.services.governance import GovernanceService
from app.telemetry import NullEventSink


def _build_test_client() -> TestClient:
    # Reset cached dependencies to avoid cross-test contamination.
    get_store.cache_clear()
    get_detection_service.cache_clear()
    get_analytics_service.cache_clear()
    get_governance_service.cache_clear()
    get_analysis_service.cache_clear()
    get_event_sink.cache_clear()

    app = create_app()
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    store = RedisWarehouse(fake_redis)
    sink = NullEventSink()
    detection = DetectionService()
    analytics = AnalyticsService(store, sink=sink)
    governance = GovernanceService(sink)
    analysis = AnalysisService(store, detection, governance, analytics, agent_public_keys={})

    app.dependency_overrides[get_store] = lambda: store
    app.dependency_overrides[get_detection_service] = lambda: detection
    app.dependency_overrides[get_event_sink] = lambda: sink
    app.dependency_overrides[get_analytics_service] = lambda: analytics
    app.dependency_overrides[get_governance_service] = lambda: governance
    app.dependency_overrides[get_analysis_service] = lambda: analysis

    return TestClient(app)


def test_full_analysis_flow_via_api():
    client = _build_test_client()
    now = datetime.now(timezone.utc).isoformat()

    payload = {
        "repo": "acme/shop",
        "pr_number": "77",
        "base_sha": "abc",
        "head_sha": "def",
        "branch": "feature/harden",
        "provenance_data": {
            "changed_lines": [
                {
                    "file_path": "services/orders.py",
                    "line_number": 10,
                    "change_type": "added",
                    "language": "python",
                    "content": "result = eval(user_input)",
                    "timestamp": now,
                    "attribution": {
                        "agent_id": "github-copilot",
                        "agent_session_id": "sess-1",
                    },
                },
                {
                    "file_path": "services/orders.py",
                    "line_number": 11,
                    "change_type": "modified",
                    "language": "python",
                    "content": "query = sanitize(user_input)",
                    "timestamp": now,
                    "attribution": {
                        "agent_id": "github-copilot",
                        "agent_session_id": "sess-1",
                    },
                },
            ]
        },
    }

    response = client.post("/v1/analysis", json=payload)
    assert response.status_code == 202
    resp_body = response.json()
    analysis_id = resp_body["analysis_id"]

    status_resp = client.get(f"/v1/analysis/{analysis_id}")
    assert status_resp.status_code == 200
    body = status_resp.json()
    assert body["findings_total"] == 1
    assert body["risk_summary"]["findings_by_category"] == {"code_execution": 1}
    assert body["decision"]["outcome"] == "allow"

    summary = client.get("/v1/analytics/summary", params={"time_window": "1d", "metric": "code_volume"})
    assert summary.status_code == 200
    data = summary.json()["result"]["data"]
    assert data and data[0]["agent_id"] == "github-copilot"
    assert data[0]["value"] == 2.0

    behavior = client.get("/v1/analytics/agents/behavior", params={"time_window": "1d"})
    assert behavior.status_code == 200
    snapshots = behavior.json()["report"]["snapshots"]
    assert snapshots
    snapshot = snapshots[0]
    assert snapshot["agent_id"] == "github-copilot"
    assert snapshot["findings_by_severity"] == {"medium": 1}

    bundle_resp = client.get(f"/v1/analysis/{analysis_id}/bundle")
    assert bundle_resp.status_code == 200
    bundle_json = bundle_resp.json()
    assert bundle_json["analysis_id"] == analysis_id
    assert bundle_json["bundle"]["payloadType"] == "application/provenance.decision+json"

    sarif_resp = client.get(f"/v1/analysis/{analysis_id}/sarif")
    assert sarif_resp.status_code == 200
    sarif_json = sarif_resp.json()
    assert sarif_json["version"] == "2.1.0"
    assert sarif_json["runs"]
