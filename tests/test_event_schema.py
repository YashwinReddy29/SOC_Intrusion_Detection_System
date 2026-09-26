from __future__ import annotations

import pytest

from app.event_schema import validate_event_v1


def event():
    return {
        "timestamp": "2026-01-15T12:00:00+00:00",
        "source_ip": "10.0.0.1",
        "destination_ip": "192.0.2.10",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "HTTPS",
        "bytes_in": 100,
        "bytes_out": 200,
        "failed_logins": 0,
        "country": "US",
        "latitude": 40.7,
        "longitude": -74.0,
    }


def test_event_schema_accepts_valid_v1_event():
    validate_event_v1(event())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_ip", "not-an-ip"),
        ("destination_port", 70000),
        ("bytes_in", -1),
        ("failed_logins", 0.5),
        ("latitude", 100),
        ("longitude", -200),
    ],
)
def test_event_schema_rejects_invalid_values(field, value):
    payload = event()
    payload[field] = value
    with pytest.raises((TypeError, ValueError)):
        validate_event_v1(payload)


def test_event_schema_requires_timezone():
    payload = event()
    payload["timestamp"] = "2026-01-15T12:00:00"
    with pytest.raises(ValueError):
        validate_event_v1(payload)
