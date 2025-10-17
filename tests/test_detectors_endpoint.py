from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import create_app
from app.dependencies import get_detection_service


def test_detectors_capabilities_endpoint(monkeypatch, tmp_path):
    get_detection_service.cache_clear()

    config_path = tmp_path / "rules.yml"
    config_path.write_text("rules:")

    with patch("app.services.detection.SemgrepDetector.CONFIG_PATH", config_path):
        app = create_app()
        client = TestClient(app)
        client.app.dependency_overrides.clear()
        get_detection_service.cache_clear()
        response = client.get("/v1/detectors/capabilities")

    assert response.status_code == 200
    payload = response.json()
    assert "request_id" in payload
    capabilities = payload["capabilities"]
    assert isinstance(capabilities, list)
    assert any(cap["name"] == "semgrep" for cap in capabilities)
