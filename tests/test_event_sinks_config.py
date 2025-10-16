import sys
import types

import pytest

from app.core.config import Settings
from app.telemetry.event_sink import sink_from_settings, BigQueryEventSink, SnowflakeEventSink, NullEventSink


def _patch_bigquery(monkeypatch):
    clients = []

    class Client:
        def __init__(self, project=None):
            self.project = project
            self.rows = []
            clients.append(self)

        @classmethod
        def from_service_account_json(cls, path, project=None):
            return cls(project=project)

        def insert_rows_json(self, table_id, rows):
            self.rows.append((table_id, rows))
            return []

    module_bigquery = types.ModuleType("google.cloud.bigquery")
    module_bigquery.Client = Client
    module_cloud = types.ModuleType("google.cloud")
    module_cloud.bigquery = module_bigquery
    module = types.ModuleType("google")
    module.cloud = module_cloud

    monkeypatch.setitem(sys.modules, "google", module)
    monkeypatch.setitem(sys.modules, "google.cloud", module_cloud)
    monkeypatch.setitem(sys.modules, "google.cloud.bigquery", module_bigquery)
    module_bigquery._clients = clients
    return module_bigquery


class _StubSnowflakeConnector:
    def __init__(self):
        self.connect_calls = []

    def connect(self, **kwargs):
        self.connect_calls.append(kwargs)

        class _Cursor:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, exc_type, exc, tb):
                return False

            def executemany(self_inner, *args, **kwargs):
                return None

        class _Conn:
            def __init__(self):
                self.closed = False

            def cursor(self):
                return _Cursor()

            def commit(self):
                return None

            def close(self):
                self.closed = True

            def is_closed(self):
                return self.closed

        return _Conn()


def _patch_snowflake(monkeypatch) -> _StubSnowflakeConnector:
    stub = _StubSnowflakeConnector()
    module = types.ModuleType("snowflake")
    module.connector = stub
    monkeypatch.setitem(sys.modules, "snowflake", module)
    monkeypatch.setitem(sys.modules, "snowflake.connector", stub)
    return stub


def test_bigquery_sink_configuration(monkeypatch):
    module = _patch_bigquery(monkeypatch)
    custom = Settings(
        timeseries_backend="bigquery",
        timeseries_project="proj",
        timeseries_dataset="dataset",
        timeseries_table="table",
        timeseries_batch_size=1,
    )
    monkeypatch.setattr("app.telemetry.event_sink.settings", custom)
    sink = sink_from_settings()
    assert isinstance(sink, BigQueryEventSink)
    sink.publish({"analysis_id": "test"})
    sink.close()
    assert module._clients[0].rows


def test_bigquery_requires_config(monkeypatch):
    _patch_bigquery(monkeypatch)
    custom = Settings(timeseries_backend="bigquery")
    monkeypatch.setattr("app.telemetry.event_sink.settings", custom)
    with pytest.raises(ValueError):
        sink_from_settings()


def test_snowflake_sink_configuration(monkeypatch):
    stub = _patch_snowflake(monkeypatch)
    custom = Settings(
        timeseries_backend="snowflake",
        timeseries_project="account",
        timeseries_database="analytics",
        timeseries_dataset="schema",
        timeseries_table="table",
        timeseries_user="svc",
        timeseries_password="secret",
    )
    monkeypatch.setattr("app.telemetry.event_sink.settings", custom)
    sink = sink_from_settings()
    assert isinstance(sink, SnowflakeEventSink)
    sink.publish({"timestamp": "2024-01-01T00:00:00Z"})
    sink.close()
    assert stub.connect_calls  # ensure configuration attempted


def test_snowflake_requires_credentials(monkeypatch):
    _patch_snowflake(monkeypatch)
    custom = Settings(
        timeseries_backend="snowflake",
        timeseries_project="account",
        timeseries_database="analytics",
        timeseries_dataset="schema",
        timeseries_table="table",
    )
    monkeypatch.setattr("app.telemetry.event_sink.settings", custom)
    with pytest.raises(ValueError):
        sink_from_settings()


def test_disabled_sink(monkeypatch):
    custom = Settings(timeseries_backend="off")
    monkeypatch.setattr("app.telemetry.event_sink.settings", custom)
    sink = sink_from_settings()
    assert isinstance(sink, NullEventSink)
