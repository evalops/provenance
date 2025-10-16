"""Event sink implementations for exporting analytics snapshots."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Protocol

from app.core.config import settings


class EventSink(Protocol):
    """Abstract sink contract."""

    def publish(self, event: dict) -> None:  # pragma: no cover - interface
        ...


class NullEventSink:
    """No-op sink used when telemetry is disabled."""

    def publish(self, event: dict) -> None:
        return None


class FileEventSink:
    """Persists events to newline-delimited JSON for downstream ingestion."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def publish(self, event: dict) -> None:
        payload = json.dumps(event, separators=(",", ":"), sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(payload)
            handle.write("\n")


def sink_from_settings() -> EventSink:
    """Factory to construct an event sink based on app settings."""

    backend = settings.timeseries_backend.lower().strip()
    if backend == "file":
        return FileEventSink(settings.timeseries_path)
    if backend in {"off", "none", "disabled"}:
        return NullEventSink()
    raise ValueError(f"Unsupported timeseries backend: {settings.timeseries_backend}")
