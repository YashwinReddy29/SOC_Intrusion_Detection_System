from __future__ import annotations

import os

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


EXPECTED_TABLES = {
    "logs",
    "users",
    "events",
    "incidents",
    "incident_audit",
    "incident_notes",
    "incident_fingerprints",
    "alembic_version",
}


def _upgrade(database_url: str) -> None:
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = database_url
    try:
        cfg = Config("alembic.ini")
        command.upgrade(cfg, "head")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


def test_migrations_build_fresh_schema(tmp_path):
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    _upgrade(url)

    engine = create_engine(url)
    assert EXPECTED_TABLES.issubset(set(inspect(engine).get_table_names()))


def test_migrations_adopt_existing_schema_without_data_loss(tmp_path):
    url = f"sqlite:///{tmp_path / 'existing.db'}"
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE logs ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "log VARCHAR NOT NULL,"
            "risk_score INTEGER NOT NULL,"
            "threat_score INTEGER NOT NULL,"
            "timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.execute(
            text(
                "INSERT INTO logs(log,risk_score,threat_score) "
                "VALUES ('existing-row', 50, 25)"
            )
        )

    _upgrade(url)

    with engine.connect() as conn:
        value = conn.execute(text("SELECT log FROM logs WHERE id=1")).scalar_one()
    assert value == "existing-row"
    assert EXPECTED_TABLES.issubset(set(inspect(engine).get_table_names()))


def test_migration_upgrade_is_repeatable(tmp_path):
    url = f"sqlite:///{tmp_path / 'repeat.db'}"
    _upgrade(url)
    _upgrade(url)
    assert EXPECTED_TABLES.issubset(set(inspect(create_engine(url)).get_table_names()))
