"""Application dependency wiring."""

from __future__ import annotations

from functools import lru_cache

from redis import Redis

from app.core.config import settings
from app.repositories.redis_store import RedisWarehouse
from app.services.analytics import AnalyticsService
from app.services.analysis import AnalysisService
from app.services.detection import DetectionService
from app.services.governance import GovernanceService
from app.telemetry import sink_from_settings, EventSink
from app.provenance.github_resolver import GitHubProvenanceResolver


@lru_cache
def get_redis_client() -> Redis:
    return Redis.from_url(settings.redis_url, decode_responses=True)


@lru_cache
def get_store() -> RedisWarehouse:
    return RedisWarehouse(get_redis_client())


@lru_cache
def get_detection_service() -> DetectionService:
    return DetectionService()


@lru_cache
def get_event_sink() -> EventSink:
    return sink_from_settings()


@lru_cache
def get_analytics_service() -> AnalyticsService:
    return AnalyticsService(get_store(), sink=get_event_sink())


@lru_cache
def get_governance_service() -> GovernanceService:
    return GovernanceService()


@lru_cache
def get_github_resolver() -> GitHubProvenanceResolver | None:
    if not settings.github_token:
        return None
    return GitHubProvenanceResolver(
        token=settings.github_token,
        base_url=settings.github_base_url,
        agent_label_prefix=settings.github_agent_label_prefix,
        cache_ttl_seconds=settings.github_cache_ttl_seconds,
    )


@lru_cache
def get_analysis_service() -> AnalysisService:
    store = get_store()
    detection = get_detection_service()
    analytics = get_analytics_service()
    governance = get_governance_service()
    github_resolver = get_github_resolver()
    return AnalysisService(store, detection, governance, analytics, github_resolver)
