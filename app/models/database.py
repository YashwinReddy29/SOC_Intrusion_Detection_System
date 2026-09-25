"""Database access shared by SQLite development and PostgreSQL production."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, LargeBinary, MetaData, String, Table, Column, create_engine, func, select
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
