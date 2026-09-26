"""Establish production-v3 schema under Alembic control.

Revision ID: 20260926_0001
Revises:
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260926_0001"
down_revision = None
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    existing = _tables()

    if "logs" not in existing:
        op.create_table(
            "logs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("log", sa.String(), nullable=False),
            sa.Column("risk_score", sa.Integer(), nullable=False),
            sa.Column("threat_score", sa.Integer(), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )

    if "users" not in existing:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("username", sa.String(length=128), nullable=False, unique=True),
            sa.Column("password", sa.LargeBinary(), nullable=False),
            sa.Column("role", sa.String(length=32), nullable=False),
        )

    if "events" not in existing:
        op.create_table(
            "events",
            sa.Column("event_id", sa.String(length=64), primary_key=True),
            sa.Column("schema_version", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("source_ip", sa.String(length=128), nullable=False),
            sa.Column("event_payload", sa.JSON(), nullable=False),
            sa.Column("detection_payload", sa.JSON(), nullable=True),
            sa.Column("model_version", sa.String(length=64), nullable=True),
            sa.Column("risk_score", sa.Float(), nullable=True),
            sa.Column("severity", sa.String(length=32), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        )

    if "incidents" not in existing:
        op.create_table(
            "incidents",
            sa.Column("incident_id", sa.String(length=64), primary_key=True),
            sa.Column("event_id", sa.String(length=64), nullable=False, unique=True),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("severity", sa.String(length=32), nullable=False),
            sa.Column("source_ip", sa.String(length=128), nullable=False),
            sa.Column("risk_score", sa.Float(), nullable=False),
            sa.Column("summary", sa.Text(), nullable=False),
            sa.Column("assignee", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )

    if "incident_audit" not in existing:
        op.create_table(
            "incident_audit",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("actor", sa.String(length=128), nullable=False),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("from_status", sa.String(length=32), nullable=True),
            sa.Column("to_status", sa.String(length=32), nullable=True),
            sa.Column("details", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_incident_audit_incident_id", "incident_audit", ["incident_id"])

    if "incident_notes" not in existing:
        op.create_table(
            "incident_notes",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("author", sa.String(length=128), nullable=False),
            sa.Column("note", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_incident_notes_incident_id", "incident_notes", ["incident_id"])

    if "incident_fingerprints" not in existing:
        op.create_table(
            "incident_fingerprints",
            sa.Column("fingerprint", sa.String(length=64), primary_key=True),
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )


def downgrade() -> None:
    # Baseline may adopt a database created by the previous create_all path.
    # Destructive downgrade is intentionally disabled to prevent accidental data loss.
    pass
