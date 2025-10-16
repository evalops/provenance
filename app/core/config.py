"""Application configuration via environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Service-wide configuration options."""

    api_v1_prefix: str = "/v1"
    default_policy_version: str = "2024-06-01"
    provenance_block_on_unknown: bool = False
    risk_high_severity_threshold: int = 1
    analytics_default_window: str = "7d"
    service_base_url: str = "http://localhost:8000"
    redis_url: str = "redis://localhost:6379/0"

    model_config = SettingsConfigDict(env_prefix="provenance_", env_file=".env", extra="ignore")


settings = Settings()
