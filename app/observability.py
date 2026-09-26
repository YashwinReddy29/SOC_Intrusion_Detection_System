"""Prometheus metrics and optional OpenTelemetry tracing."""

from __future__ import annotations

import os

from flask import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest


HTTP_REQUESTS = Counter(
    "soc_http_requests_total",
    "HTTP requests handled by the SOC API.",
    ["method", "endpoint", "status"],
)
HTTP_LATENCY = Histogram(
    "soc_http_request_duration_seconds",
    "HTTP request duration.",
    ["method", "endpoint"],
)
EVENTS = Counter(
    "soc_events_total",
    "SOC events by processing state.",
    ["state"],
)
DETECTIONS = Counter(
    "soc_detections_total",
    "ML detection decisions.",
    ["detected", "severity"],
)
DETECTION_LATENCY = Histogram(
    "soc_detection_duration_seconds",
    "End-to-end feature extraction and model-scoring duration.",
)
INCIDENTS = Counter(
    "soc_incidents_total",
    "Incidents opened by severity.",
    ["severity"],
)
DEPENDENCY_READY = Gauge(
    "soc_dependency_ready",
    "Whether a required SOC runtime dependency is ready.",
    ["dependency"],
)
KAFKA_MESSAGES = Counter(
    "soc_kafka_messages_total",
    "Kafka records handled by the detector worker.",
    ["outcome"],
)
KAFKA_LAG = Gauge(
    "soc_kafka_consumer_lag",
    "Approximate Kafka consumer lag for the detector worker.",
    ["topic", "partition"],
)

_tracing_configured = False


def metrics_response() -> Response:
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


def configure_tracing(app) -> None:
    """Enable OTLP tracing only when an exporter endpoint is configured."""
    global _tracing_configured
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return

    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    if not _tracing_configured:
        provider = TracerProvider(
            resource=Resource.create(
                {
                    "service.name": os.getenv(
                        "OTEL_SERVICE_NAME", "soc-intrusion-detection"
                    ),
                    "deployment.environment": app.config.get(
                        "APP_ENV", "development"
                    ),
                }
            )
        )
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
        )
        trace.set_tracer_provider(provider)
        _tracing_configured = True

    FlaskInstrumentor().instrument_app(app)
