"""Event sink implementations for exporting analytics snapshots."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
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


class BigQueryEventSink:
    """Buffers events for export to BigQuery."""

    def __init__(self, project: str, dataset: str, table: str) -> None:
        self.project = project
        self.dataset = dataset
        self.table = table
        self._buffer: list[dict] = []
        self._lock = threading.Lock()

    def publish(self, event: dict) -> None:
        with self._lock:
            self._buffer.append(event)
        # Placeholder for actual BigQuery load job integration.


class SnowflakeEventSink:
    """Writes events directly into a Snowflake table using the Python connector."""

    def __init__(
        self,
        account: str,
        user: str,
        password: str,
        database: str,
        schema: str,
        table: str,
        warehouse: str | None = None,
        role: str | None = None,
    ) -> None:
        try:
            import snowflake.connector  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Snowflake backend requires the snowflake-connector-python package. Install via `uv sync --group warehouse`."
            ) from exc

        self._connector = snowflake.connector
        self._conn_kwargs = {
            "account": account,
            "user": user,
            "password": password,
            "database": database,
            "schema": schema,
        }
        if warehouse:
            self._conn_kwargs["warehouse"] = warehouse
        if role:
            self._conn_kwargs["role"] = role
        self._table = table
        self._lock = threading.Lock()
        self._connection = None

    def _ensure_connection(self):
        if self._connection is None or getattr(self._connection, "is_closed", lambda: True)():
            self._connection = self._connector.connect(**self._conn_kwargs)

    def publish(self, event: dict) -> None:
        payload = json.dumps(event, separators=(",", ":"), sort_keys=True)
        event_time = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._ensure_connection()
            assert self._connection is not None  # for type checkers
            with self._connection.cursor() as cursor:
                cursor.execute(
                    f"INSERT INTO {self._table} (event_time, payload) SELECT %s::timestamp_ltz, PARSE_JSON(%s)",
                    (event_time, payload),
                )
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __del__(self):  # pragma: no cover - best effort cleanup
        try:
            self.close()
        except Exception:
            return


def sink_from_settings() -> EventSink:
    """Factory to construct an event sink based on app settings."""

    backend = settings.timeseries_backend.lower().strip()
    if backend == "file":
        return FileEventSink(settings.timeseries_path)
    if backend == "bigquery":
        if not (settings.timeseries_project and settings.timeseries_dataset and settings.timeseries_table):
            raise ValueError("BigQuery backend requires project, dataset, and table configuration")
        return BigQueryEventSink(settings.timeseries_project, settings.timeseries_dataset, settings.timeseries_table)
    if backend == "snowflake":
        if not (
            settings.timeseries_project
            and settings.timeseries_database
            and settings.timeseries_dataset
            and settings.timeseries_table
        ):
            raise ValueError(
                "Snowflake backend requires project (account), database, dataset (schema), and table configuration"
            )
        if not (settings.timeseries_user and settings.timeseries_password):
            raise ValueError("Snowflake backend requires user and password configuration")
        return SnowflakeEventSink(
            account=settings.timeseries_project,
            user=settings.timeseries_user,
            password=settings.timeseries_password,
            database=settings.timeseries_database,
            schema=settings.timeseries_dataset,
            table=settings.timeseries_table,
            warehouse=settings.timeseries_warehouse,
            role=settings.timeseries_role,
        )
    if backend in {"off", "none", "disabled"}:
        return NullEventSink()
    raise ValueError(f"Unsupported timeseries backend: {settings.timeseries_backend}")
