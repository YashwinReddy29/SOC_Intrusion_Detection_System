from __future__ import annotations

import datetime

import jwt
import pytest

from app import create_app
from app.models.database import (
    add_incident_note,
    assign_incident,
    create_event,
    create_incident,
    create_or_get_incident,
    get_incident,
    get_incident_audit,
    get_incident_notes,
    init_db,
    register_incident_fingerprint,
    transition_incident,
)


@pytest.fixture()
def db(tmp_path):
    init_db(f"sqlite:///{tmp_path / 'incident.db'}")
    create_event(
        "evt-1",
        {
            "timestamp": "2026-01-15T12:00:00+00:00",
            "source_ip": "10.0.0.1",
        },
        "10.0.0.1",
    )
    assert create_incident(
        "inc-1",
        "evt-1",
        "high",
        "10.0.0.1",
        88.0,
        "test incident",
    )


def test_incident_state_machine_and_audit(db):
    incident = transition_incident("inc-1", "acknowledged", "analyst")
    assert incident["status"] == "acknowledged"

    incident = transition_incident("inc-1", "investigating", "analyst")
    assert incident["status"] == "investigating"

    incident = transition_incident("inc-1", "resolved", "analyst")
    assert incident["status"] == "resolved"

    with pytest.raises(ValueError):
        transition_incident("inc-1", "acknowledged", "analyst")

    audit = get_incident_audit("inc-1")
    assert [row["action"] for row in audit] == [
        "status_changed",
        "status_changed",
        "status_changed",
    ]
    assert audit[0]["from_status"] == "open"
    assert audit[-1]["to_status"] == "resolved"


def test_assignment_notes_and_audit_are_persistent(db):
    assigned = assign_incident("inc-1", "alice", "admin")
    assert assigned["assignee"] == "alice"

    note = add_incident_note("inc-1", "alice", "Investigating source host.")
    assert note["author"] == "alice"

    assert get_incident("inc-1")["assignee"] == "alice"
    notes = get_incident_notes("inc-1")
    assert len(notes) == 1
    assert notes[0]["note"] == "Investigating source host."

    audit = get_incident_audit("inc-1")
    assert [row["action"] for row in audit] == [
        "assignment_changed",
        "note_added",
    ]


def test_fingerprint_registration_is_idempotent(db):
    assert register_incident_fingerprint("a" * 64, "inc-1")
    assert not register_incident_fingerprint("a" * 64, "inc-2")


def _token(secret: str, user: str, role: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return jwt.encode(
        {
            "sub": user,
            "role": role,
            "iat": now,
            "exp": now + datetime.timedelta(minutes=10),
            "iss": "soc-platform",
        },
        secret,
        algorithm="HS256",
    )


def test_incident_api_requires_bearer_token(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")
    app = create_app()
    client = app.test_client()

    response = client.get("/api/incidents")
    assert response.status_code == 401


def test_analyst_cannot_assign_another_user(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'rbac.db'}")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")
    app = create_app()

    from app.models.database import create_event, create_incident

    create_event(
        "evt-rbac",
        {"timestamp": "2026-01-15T12:00:00+00:00", "source_ip": "10.0.0.2"},
        "10.0.0.2",
    )
    create_incident(
        "inc-rbac",
        "evt-rbac",
        "medium",
        "10.0.0.2",
        70,
        "rbac",
    )

    token = _token("test-secret", "alice", "Analyst")
    response = app.test_client().patch(
        "/api/incidents/inc-rbac/assignment",
        headers={"Authorization": f"Bearer {token}"},
        json={"assignee": "bob"},
    )
    assert response.status_code == 403


def test_admin_can_assign_any_user(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'admin.db'}")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")
    app = create_app()

    from app.models.database import create_event, create_incident

    create_event(
        "evt-admin",
        {"timestamp": "2026-01-15T12:00:00+00:00", "source_ip": "10.0.0.3"},
        "10.0.0.3",
    )
    create_incident(
        "inc-admin",
        "evt-admin",
        "high",
        "10.0.0.3",
        90,
        "admin assignment",
    )

    token = _token("test-secret", "root", "Admin")
    response = app.test_client().patch(
        "/api/incidents/inc-admin/assignment",
        headers={"Authorization": f"Bearer {token}"},
        json={"assignee": "bob"},
    )
    assert response.status_code == 200
    assert response.get_json()["incident"]["assignee"] == "bob"


def test_atomic_incident_deduplication(db):
    created_id, deduplicated = create_or_get_incident(
        fingerprint="b" * 64,
        incident_id="inc-fingerprint",
        event_id="evt-fingerprint",
        severity="high",
        source_ip="10.0.0.9",
        risk_score=92.0,
        summary="fingerprint",
    )
    assert created_id == "inc-fingerprint"
    assert deduplicated is False

    existing_id, deduplicated = create_or_get_incident(
        fingerprint="b" * 64,
        incident_id="inc-other",
        event_id="evt-other",
        severity="high",
        source_ip="10.0.0.9",
        risk_score=93.0,
        summary="duplicate",
    )
    assert existing_id == "inc-fingerprint"
    assert deduplicated is True
    assert get_incident("inc-other") is None
