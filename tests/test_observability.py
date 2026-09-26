from __future__ import annotations

from app.observability import (
    DEPENDENCY_READY,
    DETECTIONS,
    EVENTS,
    HTTP_LATENCY,
    HTTP_REQUESTS,
    INCIDENTS,
    KAFKA_LAG,
    KAFKA_MESSAGES,
)


def test_metric_labels_are_bounded_and_do_not_include_sensitive_dimensions():
    metrics = {
        "http_requests": HTTP_REQUESTS._labelnames,
        "http_latency": HTTP_LATENCY._labelnames,
        "events": EVENTS._labelnames,
        "detections": DETECTIONS._labelnames,
        "incidents": INCIDENTS._labelnames,
        "dependency_ready": DEPENDENCY_READY._labelnames,
        "kafka_lag": KAFKA_LAG._labelnames,
        "kafka_messages": KAFKA_MESSAGES._labelnames,
    }
    forbidden = {"source_ip", "event_id", "username", "api_key", "incident_id", "summary"}

    for labels in metrics.values():
        assert forbidden.isdisjoint(set(labels))

    assert set(DEPENDENCY_READY._labelnames) == {"dependency"}
    assert set(KAFKA_LAG._labelnames) == {"topic", "partition"}
    assert set(KAFKA_MESSAGES._labelnames) == {"outcome"}
