from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.models.database import (
    complete_event,
    create_event,
    create_incident,
    get_event,
    get_incidents,
    init_db,
)


@pytest.fixture()
def isolated_database(tmp_path):
    path = tmp_path / "soc-test.db"
    init_db(f"sqlite:///{path}")
    return path


def sample_event() -> dict:
    return {
        "timestamp": datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc).isoformat(),
        "source_ip": "10.10.10.10",
        "destination_ip": "192.0.2.10",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "HTTPS",
        "bytes_in": 1000,
        "bytes_out": 500,
        "failed_logins": 0,
        "country": "US",
        "latitude": 40.7128,
        "longitude": -74.0060,
    }


def test_event_id_is_idempotent(isolated_database) -> None:
    event = sample_event()

    assert create_event("event-1", event, event["source_ip"])
    assert not create_event("event-1", event, event["source_ip"])

    stored = get_event("event-1")
    assert stored is not None
    assert stored["status"] == "received"
    assert stored["event_payload"]["source_ip"] == event["source_ip"]


def test_event_completion_and_incident_are_durable(isolated_database) -> None:
    event = sample_event()
    assert create_event("event-2", event, event["source_ip"])

    complete_event(
        event_id="event-2",
        detection_payload={"detected": True, "anomaly_score": 0.42},
        model_version="test-model",
        risk_score=91.5,
        severity="critical",
    )
    assert create_incident(
        incident_id="incident-2",
        event_id="event-2",
        severity="critical",
        source_ip=event["source_ip"],
        risk_score=91.5,
        summary="test incident",
    )
    assert not create_incident(
        incident_id="incident-duplicate",
        event_id="event-2",
        severity="critical",
        source_ip=event["source_ip"],
        risk_score=91.5,
        summary="duplicate",
    )

    stored = get_event("event-2")
    assert stored is not None
    assert stored["status"] == "processed"
    assert stored["model_version"] == "test-model"

    incident_rows = get_incidents()
    assert len(incident_rows) == 1
    assert incident_rows[0]["event_id"] == "event-2"
