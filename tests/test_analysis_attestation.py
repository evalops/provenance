from __future__ import annotations

import base64
from datetime import datetime, timezone

import fakeredis
import pytest
from nacl.signing import SigningKey

from app.models.domain import ChangeType
from app.repositories.redis_store import RedisWarehouse
from app.schemas.analysis import (
    AnalysisIngestionRequest,
    AttributionPayload,
    ChangedLinePayload,
    ProvenanceDataPayload,
)
from app.services.analysis import AnalysisService
from app.services.analytics import AnalyticsService
from app.services.detection import DetectionService
from app.services.governance import GovernanceService
from app.telemetry import NullEventSink


def _make_service(public_keys: dict[str, str]) -> AnalysisService:
    store = RedisWarehouse(fakeredis.FakeRedis(decode_responses=True))
    detection = DetectionService()
    analytics = AnalyticsService(store, sink=NullEventSink())
    governance = GovernanceService(NullEventSink())
    return AnalysisService(
        store,
        detection,
        governance,
        analytics,
        agent_public_keys=public_keys,
    )


def _make_request() -> AnalysisIngestionRequest:
    return AnalysisIngestionRequest(
        repo="acme/repo",
        pr_number="42",
        base_sha="abc",
        head_sha="def",
        branch="feature/secure",
        provenance_data=ProvenanceDataPayload(),
    )


def test_attestation_valid_sets_confidence():
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    public_key_b64 = base64.b64encode(verify_key.encode()).decode()
    service = _make_service({"agent-secure": public_key_b64})

    content = "print('secure')"
    content_sha = AnalysisService._hash_content(content)
    signature = signing_key.sign(content_sha.encode("utf-8")).signature
    signature_b64 = base64.b64encode(signature).decode()

    payload = ChangedLinePayload(
        file_path="src/main.py",
        line_number=1,
        change_type=ChangeType.ADDED,
        language="python",
        content=content,
        content_sha256=content_sha,
        attestation_signature=signature_b64,
        attribution=AttributionPayload(agent_id="agent-secure"),
        timestamp=datetime.now(timezone.utc),
    )

    line = service._map_changed_line("an-1", _make_request(), payload)
    assert line.content_sha256 == content_sha
    assert line.attribution.confidence_score == pytest.approx(1.0)


def test_attestation_mismatch_raises():
    service = _make_service({})
    payload = ChangedLinePayload(
        file_path="src/main.py",
        line_number=1,
        change_type=ChangeType.ADDED,
        language="python",
        content="print('oops')",
        content_sha256="deadbeef",
        attribution=AttributionPayload(agent_id="human"),
        timestamp=datetime.now(timezone.utc),
    )

    with pytest.raises(ValueError):
        service._map_changed_line("an-2", _make_request(), payload)


def test_attestation_without_signature_uses_heuristic_confidence():
    service = _make_service({})
    payload = ChangedLinePayload(
        file_path="src/main.py",
        line_number=1,
        change_type=ChangeType.ADDED,
        language="python",
        content="print('manual')",
        attribution=AttributionPayload(agent_id="manual-agent"),
        timestamp=datetime.now(timezone.utc),
    )

    line = service._map_changed_line("an-3", _make_request(), payload)
    assert line.attribution.confidence_score == pytest.approx(0.5)
