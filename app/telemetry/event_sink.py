"""Event sink implementations for exporting analytics snapshots."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import requests

from app.core.config import settings


class EventSink(Protocol):
    """Abstract sink contract."""

    def publish(self, event: dict) -> None:  # pragma: no cover - interface
        ...

    def close(self) -> None:  # pragma: no cover - interface
        ...


class NullEventSink:
    """No-op sink used when telemetry is disabled."""

    def publish(self, event: dict) -> None:
        return None

    def close(self) -> None:
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

    def close(self) -> None:
        return None


class BigQueryEventSink:
    """Writes events into BigQuery using the Python client."""

    def __init__(
        self,
        project: str,
        dataset: str,
        table: str,
        credentials_path: str | None = None,
        batch_size: int = 50,
    ) -> None:
        try:
            from google.cloud import bigquery  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "BigQuery backend requires google-cloud-bigquery. Install via `uv sync --group warehouse`."
            ) from exc

        if credentials_path:
            self._client = bigquery.Client.from_service_account_json(credentials_path, project=project)
        else:
            self._client = bigquery.Client(project=project)
        self._table_id = f"{project}.{dataset}.{table}"
        self._batch_size = batch_size
        self._buffer: list[dict] = []
        self._lock = threading.Lock()

    def publish(self, event: dict) -> None:
        row = self._to_row(event)
        with self._lock:
            self._buffer.append(row)
            if len(self._buffer) >= self._batch_size:
                self._flush_locked()

    def close(self) -> None:
        with self._lock:
            if self._buffer:
                self._flush_locked()

    def _flush_locked(self) -> None:
        errors = self._client.insert_rows_json(self._table_id, self._buffer)
        if errors:  # pragma: no cover
            raise RuntimeError(f"Failed to insert BigQuery rows: {errors}")
        self._buffer.clear()

    @staticmethod
    def _to_row(event: dict) -> dict:
        event_time = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        payload = json.loads(json.dumps(event, separators=(",", ":")))
        return {"event_time": event_time, "payload": payload}


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
        batch_size: int = 25,
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
        self._batch_size = batch_size
        self._buffer: list[tuple[str, str]] = []

    def publish(self, event: dict) -> None:
        payload = json.dumps(event, separators=(",", ":"), sort_keys=True)
        event_time = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._buffer.append((event_time, payload))
            if len(self._buffer) >= self._batch_size:
                self._flush_locked()

    def close(self) -> None:
        with self._lock:
            self._flush_locked()
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def _ensure_connection(self) -> None:
        if self._connection is None or getattr(self._connection, "is_closed", lambda: True)():
            self._connection = self._connector.connect(**self._conn_kwargs)

    def _flush_locked(self) -> None:
        if not self._buffer:
            return
        self._ensure_connection()
        assert self._connection is not None
        with self._connection.cursor() as cursor:
            cursor.executemany(
                f"INSERT INTO {self._table} (event_time, payload) SELECT %s::timestamp_ltz, PARSE_JSON(%s)",
                self._buffer,
            )
        self._connection.commit()
        self._buffer.clear()

    def __del__(self):  # pragma: no cover - best effort cleanup
        try:
            self.close()
        except Exception:
            return


class ClickHouseEventSink:
    """Writes events into ClickHouse via the HTTP interface."""

    def __init__(
        self,
        url: str,
        table: str,
        *,
        database: str | None = None,
        user: str | None = None,
        password: str | None = None,
        batch_size: int = 25,
    ) -> None:
        self._url = url.rstrip("/")
        self._table = table
        self._database = database
        self._batch_size = max(batch_size, 1)
        self._auth = (user, password) if user and password else None
        self._buffer: list[str] = []
        self._lock = threading.Lock()
        self._session = requests.Session()

    def _table_reference(self) -> str:
        if self._database and "." not in self._table:
            return f"{self._database}.{self._table}"
        return self._table

    def publish(self, event: dict) -> None:
        payload = json.dumps(event, separators=(",", ":"), sort_keys=True)
        with self._lock:
            self._buffer.append(payload)
            if len(self._buffer) >= self._batch_size:
                self._flush_locked()

    def close(self) -> None:
        with self._lock:
            self._flush_locked()
        self._session.close()

    def _flush_locked(self) -> None:
        if not self._buffer:
            return
        data = "\n".join(self._buffer)
        query = f"INSERT INTO {self._table_reference()} FORMAT JSONEachRow\n{data}\n"
        params = {"database": self._database} if self._database and "." not in self._table else None
        response = self._session.post(
            self._url,
            params=params,
            data=query.encode("utf-8"),
            auth=self._auth,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"ClickHouse insert failed ({response.status_code}): {response.text}")
        self._buffer.clear()


def sink_from_settings() -> EventSink:
    """Factory to construct an event sink based on app settings."""

    backend = settings.timeseries_backend.lower().strip()
    if backend == "file":
        return FileEventSink(settings.timeseries_path)
    if backend == "bigquery":
        if not (settings.timeseries_project and settings.timeseries_dataset and settings.timeseries_table):
            raise ValueError("BigQuery backend requires project, dataset, and table configuration")
        return BigQueryEventSink(
            project=settings.timeseries_project,
            dataset=settings.timeseries_dataset,
            table=settings.timeseries_table,
            credentials_path=settings.timeseries_credentials_path,
            batch_size=settings.timeseries_batch_size,
        )
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
            batch_size=settings.timeseries_batch_size,
        )
    if backend == "clickhouse":
        if not (settings.clickhouse_url and settings.timeseries_table):
            raise ValueError("ClickHouse backend requires PROVENANCE_CLICKHOUSE_URL and PROVENANCE_TIMESERIES_TABLE")
        return ClickHouseEventSink(
            url=settings.clickhouse_url,
            table=settings.timeseries_table,
            database=settings.clickhouse_database,
            user=settings.clickhouse_user,
            password=settings.clickhouse_password,
            batch_size=settings.timeseries_batch_size,
        )
    if backend in {"off", "none", "disabled"}:
        return NullEventSink()
    raise ValueError(f"Unsupported timeseries backend: {settings.timeseries_backend}")
