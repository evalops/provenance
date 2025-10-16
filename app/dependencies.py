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
def get_analytics_service() -> AnalyticsService:
    return AnalyticsService(get_store())


@lru_cache
def get_governance_service() -> GovernanceService:
    return GovernanceService()


@lru_cache
def get_analysis_service() -> AnalysisService:
    store = get_store()
    detection = get_detection_service()
    analytics = get_analytics_service()
    governance = get_governance_service()
    return AnalysisService(store, detection, governance, analytics)
