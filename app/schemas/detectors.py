"""API schemas for detector capability inspection."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DetectorCapability(BaseModel):
    name: str
    rule_key: str
    category: str
    description: str | None = None
    config_path: str | None = None
    config_sha256: str | None = None
    last_modified: str | None = None


class DetectorCapabilitiesResponse(BaseModel):
    capabilities: list[DetectorCapability] = Field(default_factory=list)
    request_id: str
