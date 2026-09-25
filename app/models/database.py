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


def init_db(database_url: str | None = None) -> None:
    if database_url:
        configure_database(database_url)
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
