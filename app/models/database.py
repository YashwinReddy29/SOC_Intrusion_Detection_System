"""Database access shared by SQLite development and PostgreSQL production."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    func,
    select,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError


metadata = MetaData()

logs = Table(
    "logs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("log", String, nullable=False),
    Column("risk_score", Integer, nullable=False),
    Column("threat_score", Integer, nullable=False),
    Column("timestamp", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(128), nullable=False, unique=True),
    Column("password", LargeBinary, nullable=False),
    Column("role", String(32), nullable=False),
)

events = Table(
    "events",
    metadata,
    Column("event_id", String(64), primary_key=True),
    Column("schema_version", String(16), nullable=False, default="1"),
    Column("status", String(32), nullable=False, default="received"),
    Column("source_ip", String(128), nullable=False),
    Column("event_payload", JSON, nullable=False),
    Column("detection_payload", JSON, nullable=True),
    Column("model_version", String(64), nullable=True),
    Column("risk_score", Float, nullable=True),
    Column("severity", String(32), nullable=True),
    Column("error", Text, nullable=True),
    Column("received_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("processed_at", DateTime(timezone=True), nullable=True),
)

incidents = Table(
    "incidents",
    metadata,
    Column("incident_id", String(64), primary_key=True),
    Column("event_id", String(64), nullable=False, unique=True),
    Column("status", String(32), nullable=False, default="open"),
    Column("severity", String(32), nullable=False),
    Column("source_ip", String(128), nullable=False),
    Column("risk_score", Float, nullable=False),
    Column("summary", Text, nullable=False),
    Column("assignee", String(128), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()),
)

incident_audit = Table(
    "incident_audit",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("actor", String(128), nullable=False),
    Column("action", String(64), nullable=False),
    Column("from_status", String(32), nullable=True),
    Column("to_status", String(32), nullable=True),
    Column("details", JSON, nullable=False, default=dict),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

incident_notes = Table(
    "incident_notes",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", String(64), nullable=False, index=True),
    Column("author", String(128), nullable=False),
    Column("note", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

incident_fingerprints = Table(
    "incident_fingerprints",
    metadata,
    Column("fingerprint", String(64), primary_key=True),
    Column("incident_id", String(64), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

_engine: Engine | None = None


def configure_database(database_url: str) -> None:
    global _engine
    options = {"pool_pre_ping": True, "future": True}
    if database_url.startswith("sqlite:"):
        options["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(database_url, **options)


def _get_engine() -> Engine:
    if _engine is None:
        configure_database("sqlite:///soc.db")
    assert _engine is not None
    return _engine


def init_db(database_url: str | None = None, create_schema: bool = True) -> None:
    if database_url:
        configure_database(database_url)
    if create_schema:
        metadata.create_all(_get_engine())


def ping_db() -> None:
    with _get_engine().connect() as conn:
        conn.exec_driver_sql("SELECT 1")


def insert_log(log: str, risk_score: int, threat_score: int) -> None:
    with _get_engine().begin() as conn:
        conn.execute(
            logs.insert().values(
                log=str(log),
                risk_score=int(risk_score),
                threat_score=int(threat_score),
            )
        )


def get_logs(limit: int | None = None) -> list[tuple]:
    statement = select(logs).order_by(logs.c.id.desc())
    if limit is not None:
        statement = statement.limit(max(0, int(limit)))

    with _get_engine().connect() as conn:
        rows = conn.execute(statement).all()

    return [tuple(row) for row in rows]


def create_user(username: str, password_hash: bytes, role: str) -> None:
    try:
        with _get_engine().begin() as conn:
            conn.execute(
                users.insert().values(
                    username=username,
                    password=password_hash,
                    role=role,
                )
            )
    except IntegrityError as exc:
        raise ValueError("username already exists") from exc


def get_user_credentials(username: str) -> tuple[bytes, str] | None:
    statement = (
        select(users.c.password, users.c.role)
        .where(users.c.username == username)
        .limit(1)
    )
    with _get_engine().connect() as conn:
        row = conn.execute(statement).first()
    if row is None:
        return None
    return bytes(row.password), str(row.role)


def create_event(event_id: str, event_payload: dict, source_ip: str, schema_version: str = "1") -> bool:
    """Create an event once. Returns False for a duplicate event_id."""
    try:
        with _get_engine().begin() as conn:
            conn.execute(
                events.insert().values(
                    event_id=event_id,
                    schema_version=schema_version,
                    status="received",
                    source_ip=source_ip,
                    event_payload=event_payload,
                )
            )
        return True
    except IntegrityError:
        return False


def mark_event_processing(event_id: str) -> None:
    with _get_engine().begin() as conn:
        conn.execute(
            update(events)
            .where(events.c.event_id == event_id)
            .values(status="processing", error=None)
        )


def complete_event(
    event_id: str,
    detection_payload: dict,
    model_version: str,
    risk_score: float,
    severity: str,
) -> None:
    with _get_engine().begin() as conn:
        conn.execute(
            update(events)
            .where(events.c.event_id == event_id)
            .values(
                status="processed",
                detection_payload=detection_payload,
                model_version=model_version,
                risk_score=float(risk_score),
                severity=severity,
                processed_at=func.now(),
                error=None,
            )
        )


def fail_event(event_id: str, error: str) -> None:
    with _get_engine().begin() as conn:
        conn.execute(
            update(events)
            .where(events.c.event_id == event_id)
            .values(
                status="failed",
                error=str(error)[:2000],
                processed_at=func.now(),
            )
        )


def get_event(event_id: str) -> dict | None:
    with _get_engine().connect() as conn:
        row = conn.execute(
            select(events).where(events.c.event_id == event_id).limit(1)
        ).mappings().first()
    return dict(row) if row else None


def create_incident(
    incident_id: str,
    event_id: str,
    severity: str,
    source_ip: str,
    risk_score: float,
    summary: str,
) -> bool:
    try:
        with _get_engine().begin() as conn:
            conn.execute(
                incidents.insert().values(
                    incident_id=incident_id,
                    event_id=event_id,
                    status="open",
                    severity=severity,
                    source_ip=source_ip,
                    risk_score=float(risk_score),
                    summary=summary,
                )
            )
        return True
    except IntegrityError:
        return False


def get_incidents(limit: int = 100) -> list[dict]:
    statement = (
        select(incidents)
        .order_by(incidents.c.created_at.desc())
        .limit(max(1, min(int(limit), 1000)))
    )
    with _get_engine().connect() as conn:
        rows = conn.execute(statement).mappings().all()
    return [dict(row) for row in rows]

INCIDENT_TRANSITIONS = {
    "open": {"acknowledged", "investigating", "resolved", "false_positive"},
    "acknowledged": {"investigating", "resolved", "false_positive"},
    "investigating": {"acknowledged", "resolved", "false_positive"},
    "resolved": {"investigating"},
    "false_positive": {"investigating"},
}


def get_incident(incident_id: str) -> dict | None:
    with _get_engine().connect() as conn:
        row = conn.execute(
            select(incidents).where(incidents.c.incident_id == incident_id).limit(1)
        ).mappings().first()
    return dict(row) if row else None


def register_incident_fingerprint(fingerprint: str, incident_id: str) -> bool:
    try:
        with _get_engine().begin() as conn:
            conn.execute(
                incident_fingerprints.insert().values(
                    fingerprint=fingerprint,
                    incident_id=incident_id,
                )
            )
        return True
    except IntegrityError:
        return False


def incident_for_fingerprint(fingerprint: str) -> str | None:
    with _get_engine().connect() as conn:
        row = conn.execute(
            select(incident_fingerprints.c.incident_id)
            .where(incident_fingerprints.c.fingerprint == fingerprint)
            .limit(1)
        ).first()
    return str(row[0]) if row else None


def append_incident_audit(
    incident_id: str,
    actor: str,
    action: str,
    *,
    from_status: str | None = None,
    to_status: str | None = None,
    details: dict | None = None,
) -> None:
    with _get_engine().begin() as conn:
        conn.execute(
            incident_audit.insert().values(
                incident_id=incident_id,
                actor=actor,
                action=action,
                from_status=from_status,
                to_status=to_status,
                details=details or {},
            )
        )


def transition_incident(incident_id: str, to_status: str, actor: str) -> dict:
    target = str(to_status).strip().lower()
    with _get_engine().begin() as conn:
        row = conn.execute(
            select(incidents)
            .where(incidents.c.incident_id == incident_id)
            .limit(1)
        ).mappings().first()
        if row is None:
            raise KeyError("incident not found")

        current = str(row["status"])
        if target == current:
            return dict(row)
        if target not in INCIDENT_TRANSITIONS.get(current, set()):
            raise ValueError(f"invalid incident transition: {current} -> {target}")

        result = conn.execute(
            update(incidents)
            .where(
                (incidents.c.incident_id == incident_id)
                & (incidents.c.status == current)
            )
            .values(status=target, updated_at=func.now())
        )
        if result.rowcount != 1:
            raise RuntimeError("incident changed concurrently; retry the request")

        conn.execute(
            incident_audit.insert().values(
                incident_id=incident_id,
                actor=actor,
                action="status_changed",
                from_status=current,
                to_status=target,
                details={},
            )
        )

        updated_row = conn.execute(
            select(incidents)
            .where(incidents.c.incident_id == incident_id)
            .limit(1)
        ).mappings().first()
    return dict(updated_row)


def assign_incident(incident_id: str, assignee: str | None, actor: str) -> dict:
    normalized = assignee.strip() if isinstance(assignee, str) else None
    normalized = normalized or None
    with _get_engine().begin() as conn:
        row = conn.execute(
            select(incidents)
            .where(incidents.c.incident_id == incident_id)
            .limit(1)
        ).mappings().first()
        if row is None:
            raise KeyError("incident not found")

        previous = row["assignee"]
        conn.execute(
            update(incidents)
            .where(incidents.c.incident_id == incident_id)
            .values(assignee=normalized, updated_at=func.now())
        )
        conn.execute(
            incident_audit.insert().values(
                incident_id=incident_id,
                actor=actor,
                action="assignment_changed",
                details={"from": previous, "to": normalized},
            )
        )
        updated_row = conn.execute(
            select(incidents)
            .where(incidents.c.incident_id == incident_id)
            .limit(1)
        ).mappings().first()
    return dict(updated_row)


def add_incident_note(incident_id: str, author: str, note: str) -> dict:
    text = str(note).strip()
    if not text:
        raise ValueError("note must not be empty")
    if len(text) > 4000:
        raise ValueError("note must be 4000 characters or fewer")

    with _get_engine().begin() as conn:
        exists = conn.execute(
            select(incidents.c.incident_id)
            .where(incidents.c.incident_id == incident_id)
            .limit(1)
        ).first()
        if exists is None:
            raise KeyError("incident not found")

        result = conn.execute(
            incident_notes.insert().values(
                incident_id=incident_id,
                author=author,
                note=text,
            )
        )
        note_id = result.inserted_primary_key[0]
        conn.execute(
            incident_audit.insert().values(
                incident_id=incident_id,
                actor=author,
                action="note_added",
                details={"note_id": note_id},
            )
        )
        row = conn.execute(
            select(incident_notes)
            .where(incident_notes.c.id == note_id)
            .limit(1)
        ).mappings().first()
    return dict(row)


def get_incident_notes(incident_id: str) -> list[dict]:
    with _get_engine().connect() as conn:
        rows = conn.execute(
            select(incident_notes)
            .where(incident_notes.c.incident_id == incident_id)
            .order_by(incident_notes.c.id.asc())
        ).mappings().all()
    return [dict(row) for row in rows]


def get_incident_audit(incident_id: str) -> list[dict]:
    with _get_engine().connect() as conn:
        rows = conn.execute(
            select(incident_audit)
            .where(incident_audit.c.incident_id == incident_id)
            .order_by(incident_audit.c.id.asc())
        ).mappings().all()
    return [dict(row) for row in rows]


def create_or_get_incident(
    *,
    fingerprint: str,
    incident_id: str,
    event_id: str,
    severity: str,
    source_ip: str,
    risk_score: float,
    summary: str,
) -> tuple[str, bool]:
    """Atomically create the fingerprint and incident, or return its existing incident."""
    try:
        with _get_engine().begin() as conn:
            conn.execute(
                incident_fingerprints.insert().values(
                    fingerprint=fingerprint,
                    incident_id=incident_id,
                )
            )
            conn.execute(
                incidents.insert().values(
                    incident_id=incident_id,
                    event_id=event_id,
                    status="open",
                    severity=severity,
                    source_ip=source_ip,
                    risk_score=float(risk_score),
                    summary=summary,
                )
            )
        return incident_id, False
    except IntegrityError:
        with _get_engine().connect() as conn:
            existing = conn.execute(
                select(incident_fingerprints.c.incident_id)
                .where(incident_fingerprints.c.fingerprint == fingerprint)
                .limit(1)
            ).first()
            if existing is not None:
                return str(existing[0]), True

            by_event = conn.execute(
                select(incidents.c.incident_id)
                .where(incidents.c.event_id == event_id)
                .limit(1)
            ).first()
            if by_event is not None:
                return str(by_event[0]), True
        raise


def create_or_get_incident(
    *,
    fingerprint: str,
    incident_id: str,
    event_id: str,
    severity: str,
    source_ip: str,
    risk_score: float,
    summary: str,
) -> tuple[str, bool]:
    """Atomically create the fingerprint and incident, or return its existing incident."""
    try:
        with _get_engine().begin() as conn:
            conn.execute(
                incident_fingerprints.insert().values(
                    fingerprint=fingerprint,
                    incident_id=incident_id,
                )
            )
            conn.execute(
                incidents.insert().values(
                    incident_id=incident_id,
                    event_id=event_id,
                    status="open",
                    severity=severity,
                    source_ip=source_ip,
                    risk_score=float(risk_score),
                    summary=summary,
                )
            )
        return incident_id, False
    except IntegrityError:
        with _get_engine().connect() as conn:
            existing = conn.execute(
                select(incident_fingerprints.c.incident_id)
                .where(incident_fingerprints.c.fingerprint == fingerprint)
                .limit(1)
            ).first()
            if existing is not None:
                return str(existing[0]), True

            by_event = conn.execute(
                select(incidents.c.incident_id)
                .where(incidents.c.event_id == event_id)
                .limit(1)
            ).first()
            if by_event is not None:
                return str(by_event[0]), True
        raise


def create_or_get_incident(
    *,
    fingerprint: str,
    incident_id: str,
    event_id: str,
    severity: str,
    source_ip: str,
    risk_score: float,
    summary: str,
) -> tuple[str, bool]:
    """Atomically create the fingerprint and incident, or return its existing incident."""
    try:
        with _get_engine().begin() as conn:
            conn.execute(
                incident_fingerprints.insert().values(
                    fingerprint=fingerprint,
                    incident_id=incident_id,
                )
            )
            conn.execute(
                incidents.insert().values(
                    incident_id=incident_id,
                    event_id=event_id,
                    status="open",
                    severity=severity,
                    source_ip=source_ip,
                    risk_score=float(risk_score),
                    summary=summary,
                )
            )
        return incident_id, False
    except IntegrityError:
        with _get_engine().connect() as conn:
            existing = conn.execute(
                select(incident_fingerprints.c.incident_id)
                .where(incident_fingerprints.c.fingerprint == fingerprint)
                .limit(1)
            ).first()
            if existing is not None:
                return str(existing[0]), True

            by_event = conn.execute(
                select(incidents.c.incident_id)
                .where(incidents.c.event_id == event_id)
                .limit(1)
            ).first()
            if by_event is not None:
                return str(by_event[0]), True
        raise


def create_or_get_incident(
    *,
    fingerprint: str,
    incident_id: str,
    event_id: str,
    severity: str,
    source_ip: str,
    risk_score: float,
    summary: str,
) -> tuple[str, bool]:
    """Atomically create the fingerprint and incident, or return its existing incident."""
    try:
        with _get_engine().begin() as conn:
            conn.execute(
                incident_fingerprints.insert().values(
                    fingerprint=fingerprint,
                    incident_id=incident_id,
                )
            )
            conn.execute(
                incidents.insert().values(
                    incident_id=incident_id,
                    event_id=event_id,
                    status="open",
                    severity=severity,
                    source_ip=source_ip,
                    risk_score=float(risk_score),
                    summary=summary,
                )
            )
        return incident_id, False
    except IntegrityError:
        with _get_engine().connect() as conn:
            existing = conn.execute(
                select(incident_fingerprints.c.incident_id)
                .where(incident_fingerprints.c.fingerprint == fingerprint)
                .limit(1)
            ).first()
            if existing is not None:
                return str(existing[0]), True

            by_event = conn.execute(
                select(incidents.c.incident_id)
                .where(incidents.c.event_id == event_id)
                .limit(1)
            ).first()
            if by_event is not None:
                return str(by_event[0]), True
        raise
