import sys
import types
from datetime import datetime, timezone


class _StubCursor:
    def __init__(self):
        self.executed = []

    def execute(self, sql, params):
        self.executed.append((sql, params))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _StubConnection:
    def __init__(self):
        self.cursor_instance = _StubCursor()
        self.commits = 0
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True

    def is_closed(self):
        return self.closed


class _StubConnector:
    def __init__(self):
        self.connections: list[tuple[_StubConnection, dict]] = []

    def connect(self, **kwargs):
        conn = _StubConnection()
        self.connections.append((conn, kwargs))
        return conn


def test_snowflake_event_sink_publish(monkeypatch):
    stub_connector = _StubConnector()
    module = types.ModuleType("snowflake")
    module.connector = stub_connector
    monkeypatch.setitem(sys.modules, "snowflake", module)
    monkeypatch.setitem(sys.modules, "snowflake.connector", stub_connector)

    from app.telemetry.event_sink import SnowflakeEventSink

    sink = SnowflakeEventSink(
        account="acct",
        user="user",
        password="pass",
        database="analytics",
        schema="public",
        table="analytics.events",
        warehouse="wh",
        role="role",
    )

    sink.publish({"analysis_id": "an", "timestamp": datetime.now(timezone.utc).isoformat()})

    assert stub_connector.connections
    connection, kwargs = stub_connector.connections[0]
    assert kwargs["account"] == "acct"
    assert kwargs["warehouse"] == "wh"
    assert connection.commits == 1
    assert connection.cursor_instance.executed
