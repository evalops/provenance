"""OpenTelemetry metrics instrumentation helpers."""

from __future__ import annotations

import logging
from typing import Optional

from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

from app.core.config import settings

_logger = logging.getLogger(__name__)

_metrics_enabled = False
_meter = None
_provider: MeterProvider | None = None
_analysis_duration_hist = None
_analysis_findings_counter = None
_analysis_ingestion_counter = None


def configure_metrics() -> None:
    """Initialise the metrics provider if enabled via settings."""

    global _metrics_enabled, _meter, _analysis_duration_hist, _analysis_findings_counter, _analysis_ingestion_counter, _provider

    if not settings.otel_enabled:
        return
    if _metrics_enabled:
        return

    exporter_name = settings.otel_exporter.lower().strip()
    metric_readers = []

    if exporter_name == "console":
        exporter = ConsoleMetricExporter()
        metric_readers.append(PeriodicExportingMetricReader(exporter))
    elif exporter_name == "prometheus":
        try:
            from opentelemetry.exporter.prometheus import PrometheusMetricReader  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Prometheus exporter selected but opentelemetry-exporter-prometheus is not installed."
            ) from exc
        metric_readers.append(PrometheusMetricReader(port=settings.otel_prometheus_port))
    elif exporter_name == "otlp":
        try:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "OTLP exporter selected but opentelemetry-exporter-otlp is not installed."
            ) from exc
        endpoint = settings.otel_otlp_endpoint
        exporter = OTLPMetricExporter(endpoint=endpoint) if endpoint else OTLPMetricExporter()
        metric_readers.append(PeriodicExportingMetricReader(exporter))
    else:
        _logger.warning("Unsupported OTEL exporter '%s'; defaulting to console", exporter_name)
        metric_readers.append(PeriodicExportingMetricReader(ConsoleMetricExporter()))

    _provider = MeterProvider(metric_readers=metric_readers, resource=Resource.create({"service.name": "provenance"}))
    metrics.set_meter_provider(_provider)
    _meter = metrics.get_meter("provenance")
    _analysis_duration_hist = _meter.create_histogram(
        name="provenance.analysis.duration",
        unit="s",
        description="Analysis execution duration in seconds",
    )
    _analysis_findings_counter = _meter.create_counter(
        name="provenance.analysis.findings",
        unit="1",
        description="Total findings produced per analysis",
    )
    _analysis_ingestion_counter = _meter.create_counter(
        name="provenance.analysis.ingestions",
        unit="1",
        description="Total analyses ingested",
    )
    _metrics_enabled = True


def record_analysis_duration(seconds: float) -> None:
    if _metrics_enabled and _analysis_duration_hist is not None:
        _analysis_duration_hist.record(max(seconds, 0.0))


def record_analysis_findings(count: int) -> None:
    if _metrics_enabled and _analysis_findings_counter is not None and count:
        _analysis_findings_counter.add(count)


def increment_analysis_ingestion() -> None:
    if _metrics_enabled and _analysis_ingestion_counter is not None:
        _analysis_ingestion_counter.add(1)


def shutdown_metrics() -> None:
    global _metrics_enabled, _provider
    if _metrics_enabled and _provider is not None:
        try:
            _provider.shutdown()
        except Exception:  # pragma: no cover - defensive
            _logger.exception("Failed to shutdown metrics provider")
        finally:
            _metrics_enabled = False
            _provider = None
