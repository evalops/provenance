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
    semgrep_config_path: str | None = None
    timeseries_backend: str = "file"
    timeseries_path: str = "data/timeseries_events.jsonl"
    timeseries_project: str | None = None
    timeseries_dataset: str | None = None
    timeseries_table: str | None = None
    timeseries_database: str | None = None
    timeseries_credentials_path: str | None = None
    timeseries_user: str | None = None
    timeseries_password: str | None = None
    timeseries_role: str | None = None
    timeseries_warehouse: str | None = None
    timeseries_batch_size: int = 25
    otel_enabled: bool = False
    otel_exporter: str = "console"

    model_config = SettingsConfigDict(env_prefix="provenance_", env_file=".env", extra="ignore")


settings = Settings()
