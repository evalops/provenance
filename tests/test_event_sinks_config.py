import pytest

from app.core.config import Settings
from app.telemetry.event_sink import sink_from_settings, BigQueryEventSink, SnowflakeEventSink, NullEventSink


def test_bigquery_sink_configuration(monkeypatch):
    custom = Settings(
        timeseries_backend="bigquery",
        timeseries_project="proj",
        timeseries_dataset="dataset",
        timeseries_table="table",
    )
    monkeypatch.setattr("app.telemetry.event_sink.settings", custom)
    sink = sink_from_settings()
    assert isinstance(sink, BigQueryEventSink)


def test_bigquery_requires_config(monkeypatch):
    custom = Settings(timeseries_backend="bigquery")
    monkeypatch.setattr("app.telemetry.event_sink.settings", custom)
    with pytest.raises(ValueError):
        sink_from_settings()


def test_snowflake_sink_configuration(monkeypatch):
    custom = Settings(
        timeseries_backend="snowflake",
        timeseries_project="account",
        timeseries_dataset="schema",
        timeseries_table="table",
    )
    monkeypatch.setattr("app.telemetry.event_sink.settings", custom)
    sink = sink_from_settings()
    assert isinstance(sink, SnowflakeEventSink)


def test_disabled_sink(monkeypatch):
    custom = Settings(timeseries_backend="off")
    monkeypatch.setattr("app.telemetry.event_sink.settings", custom)
    sink = sink_from_settings()
    assert isinstance(sink, NullEventSink)
