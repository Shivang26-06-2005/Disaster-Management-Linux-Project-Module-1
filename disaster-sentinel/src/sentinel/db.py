"""Shared data-centric repository (slide 13, model 2). PostgreSQL, TimescaleDB if present.

Components never call each other. They read and write these tables, each with its
own database role, so the grants in ``ROLE_GRANTS`` enforce who may touch what.
"""
from __future__ import annotations

import logging
import os
import re
from functools import lru_cache

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from .config import database_url

log = logging.getLogger("sentinel.db")

meta = sa.MetaData()
TS = sa.DateTime(timezone=True)

nodes = sa.Table(
    "nodes", meta,
    sa.Column("id", sa.String(64), primary_key=True),
    sa.Column("token_hash", sa.String(64), nullable=False),
    sa.Column("hostname", sa.String(255)),
    sa.Column("region", sa.String(120)),
    sa.Column("lat", sa.Float),
    sa.Column("lon", sa.Float),
    sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    sa.Column("last_seen", TS),
    sa.Column("clock_skew_s", sa.Float),
    sa.Column("agent", JSONB),
)

metrics = sa.Table(
    "metrics", meta,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("ts", TS, primary_key=True),
    sa.Column("node_id", sa.String(64), nullable=False),
    sa.Column("cpu", sa.Float),
    sa.Column("mem", sa.Float),
    sa.Column("disk", sa.Float),
    sa.Column("load1", sa.Float),
    sa.Column("processed", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Index("ix_metrics_node_ts", "node_id", "ts"),
    sa.Index("ix_metrics_unprocessed", "id", postgresql_where=sa.text("NOT processed")),
)

log_events = sa.Table(
    "log_events", meta,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("ts", TS, primary_key=True),
    sa.Column("node_id", sa.String(64), nullable=False),
    sa.Column("batch_id", sa.String(36), nullable=False),
    sa.Column("seq", sa.Integer, nullable=False),
    sa.Column("source", sa.String(120), nullable=False),
    sa.Column("line", sa.Text, nullable=False),
    sa.Column("processed", sa.Boolean, nullable=False, server_default=sa.false()),
    sa.Index("ix_logs_node_ts", "node_id", "ts"),
    sa.Index("ix_logs_batch", "batch_id"),
    sa.Index("ix_logs_unprocessed", "id", postgresql_where=sa.text("NOT processed")),
)

ingest_batches = sa.Table(
    "ingest_batches", meta,
    sa.Column("batch_id", sa.String(36), primary_key=True),
    sa.Column("node_id", sa.String(64), nullable=False),
    sa.Column("received_at", TS, nullable=False, server_default=sa.func.now()),
)

detections = sa.Table(
    "detections", meta,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("ts", TS, nullable=False),
    sa.Column("node_id", sa.String(64), nullable=False),
    sa.Column("modality", sa.String(16), nullable=False),
    sa.Column("name", sa.String(64), nullable=False),
    sa.Column("strength", sa.String(8), nullable=False),
    sa.Column("attrs", JSONB, nullable=False, server_default="{}"),
    sa.Index("ix_detections_node_ts", "node_id", "ts"),
)

hazard_events = sa.Table(
    "hazard_events", meta,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("source", sa.String(16), nullable=False),
    sa.Column("external_id", sa.String(120), nullable=False),
    sa.Column("hazard_type", sa.String(32), nullable=False),
    sa.Column("severity", sa.String(16), nullable=False),
    sa.Column("title", sa.Text, nullable=False),
    sa.Column("lat", sa.Float),
    sa.Column("lon", sa.Float),
    sa.Column("radius_km", sa.Float, nullable=False),
    sa.Column("verified", sa.Boolean, nullable=False),
    sa.Column("starts_at", TS, nullable=False),
    sa.Column("expires_at", TS, nullable=False),
    sa.Column("raw", JSONB),
    sa.Column("first_seen", TS, nullable=False, server_default=sa.func.now()),
    sa.UniqueConstraint("source", "external_id", name="uq_hazard_source_ext"),
    sa.Index("ix_hazard_active", "expires_at"),
)

incidents = sa.Table(
    "incidents", meta,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("node_id", sa.String(64), nullable=False),
    sa.Column("category", sa.String(32), nullable=False),
    sa.Column("severity", sa.String(8), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),  # open, resolved
    sa.Column("title", sa.Text, nullable=False),
    sa.Column("summary", sa.Text, nullable=False),
    sa.Column("reasons", JSONB, nullable=False),
    sa.Column("attrs", JSONB, nullable=False, server_default="{}"),
    sa.Column("hazard_ids", JSONB, nullable=False, server_default="[]"),
    sa.Column("noticed_at", TS, nullable=False),
    sa.Column("last_signal_at", TS, nullable=False),
    sa.Column("resolved_at", TS),
    sa.Column("resolved_by", sa.String(64)),
    sa.Column("playbook_at", TS),
    sa.Column("escalated_at", TS),
    sa.Column("certin_type", sa.Text),
    sa.Column("certin_deadline", TS),
    sa.Column("certin_reported_at", TS),
    sa.Column("certin_reference", sa.String(120)),
    sa.Index(
        "uq_open_incident", "node_id", "category", unique=True,
        postgresql_where=sa.text("status = 'open'"),
    ),
)

recovery_actions = sa.Table(
    "recovery_actions", meta,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("incident_id", sa.BigInteger, sa.ForeignKey("incidents.id"), nullable=False),
    sa.Column("node_id", sa.String(64), nullable=False),
    sa.Column("action", sa.String(32), nullable=False),
    sa.Column("arg", sa.String(255)),
    # awaiting_approval, pending, claimed, done, failed, expired, rejected
    sa.Column("status", sa.String(20), nullable=False),
    sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    sa.Column("expires_at", TS, nullable=False),
    sa.Column("claimed_at", TS),
    sa.Column("finished_at", TS),
    sa.Column("exit_code", sa.Integer),
    sa.Column("dry_run", sa.Boolean),
    sa.Column("output", sa.Text),
    sa.Index("ix_actions_node_status", "node_id", "status"),
)

notifications = sa.Table(
    "notifications", meta,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("incident_id", sa.BigInteger),
    sa.Column("channel", sa.String(16), nullable=False),
    sa.Column("subject", sa.Text, nullable=False),
    sa.Column("body", sa.Text, nullable=False),
    sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
    sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
    sa.Column("last_error", sa.Text),
    sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    sa.Column("sent_at", TS),
)

crisis_reports = sa.Table(
    "crisis_reports", meta,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    sa.Column("text", sa.Text),
    sa.Column("text_hash", sa.String(64)),
    sa.Column("image_path", sa.String(255)),   # relative path, slide 14 storage decoupling
    sa.Column("severity", sa.String(32), nullable=False),
    sa.Column("reliability", sa.Float, nullable=False),
    sa.Column("result", JSONB, nullable=False),
    sa.Column("hazard_type", sa.String(32)),
    sa.Column("location", sa.String(120)),
    sa.Column("lat", sa.Float),
    sa.Column("lon", sa.Float),
    sa.Column("verification", sa.String(32), nullable=False),
    sa.Column("duplicate_of", sa.BigInteger),
    sa.Column("submitted_by", sa.String(64)),
)

audit_log = sa.Table(
    "audit_log", meta,
    sa.Column("seq", sa.BigInteger, primary_key=True, autoincrement=False),
    sa.Column("ts", TS, nullable=False),
    sa.Column("kind", sa.String(48), nullable=False),
    sa.Column("payload", sa.Text, nullable=False),
    sa.Column("prev_hash", sa.String(64), nullable=False),
    sa.Column("hash", sa.String(64), nullable=False),
)

audit_head = sa.Table(
    "audit_head", meta,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
    sa.Column("seq", sa.BigInteger, nullable=False),
    sa.Column("hash", sa.String(64), nullable=False),
    sa.CheckConstraint("id = 1", name="audit_head_single_row"),
)

kv = sa.Table(
    "kv", meta,
    sa.Column("key", sa.String(64), primary_key=True),
    sa.Column("value", JSONB, nullable=False),
)

GENESIS = "0" * 64

_TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_log_no_change ON audit_log;
CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();
"""

# Least privilege per component. "ALL" here never includes audit_log rewrites.
ROLE_GRANTS: dict[str, dict[str, str]] = {
    "sentinel_ingest": {
        "nodes": "SELECT, UPDATE",
        "metrics": "INSERT",
        "log_events": "INSERT",
        "ingest_batches": "SELECT, INSERT",
        "recovery_actions": "SELECT, UPDATE",
        "audit_log": "SELECT, INSERT",
        "audit_head": "SELECT, UPDATE",
    },
    "sentinel_analytics": {
        "nodes": "SELECT",
        "metrics": "SELECT, UPDATE, DELETE",
        "log_events": "SELECT, UPDATE, DELETE",
        "ingest_batches": "SELECT, DELETE",
        "detections": "SELECT, INSERT, DELETE",
        "hazard_events": "SELECT",
        "incidents": "SELECT, INSERT, UPDATE",
        "recovery_actions": "SELECT",
        "audit_log": "SELECT, INSERT",
        "audit_head": "SELECT, UPDATE",
        "kv": "SELECT, INSERT, UPDATE",
    },
    "sentinel_hazards": {
        "hazard_events": "SELECT, INSERT, UPDATE",
        "audit_log": "SELECT, INSERT",
        "audit_head": "SELECT, UPDATE",
        "kv": "SELECT, INSERT, UPDATE",
    },
    "sentinel_recovery": {
        "nodes": "SELECT",
        "incidents": "SELECT, UPDATE",
        "recovery_actions": "SELECT, INSERT, UPDATE",
        "notifications": "SELECT, INSERT, UPDATE",
        "audit_log": "SELECT, INSERT",
        "audit_head": "SELECT, UPDATE",
    },
    "sentinel_dashboard": {
        "nodes": "SELECT, INSERT",
        "metrics": "SELECT",
        "log_events": "SELECT",
        "detections": "SELECT",
        "hazard_events": "SELECT, INSERT, UPDATE",
        "incidents": "SELECT, UPDATE",
        "recovery_actions": "SELECT, UPDATE",
        "notifications": "SELECT",
        "crisis_reports": "SELECT, INSERT",
        "audit_log": "SELECT, INSERT",
        "audit_head": "SELECT, UPDATE",
        "kv": "SELECT",
    },
}


def timescale_setup(conn: sa.Connection) -> bool:
    """Turn metrics and logs into hypertables when the extension is installed."""
    available = conn.execute(
        sa.text("SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb'")
    ).first()
    if not available:
        log.info("TimescaleDB not installed, using plain PostgreSQL tables")
        return False
    conn.execute(sa.text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
    for table in ("metrics", "log_events"):
        conn.execute(sa.text(
            f"SELECT create_hypertable('{table}', 'ts', if_not_exists => TRUE, migrate_data => TRUE)"
        ))
    return True


def migrate(engine: sa.Engine, role_passwords: dict[str, str] | None = None) -> None:
    """Create the schema, triggers and per-component roles. Safe to run repeatedly."""
    meta.create_all(engine)
    with engine.begin() as conn:
        for statement in _split_plpgsql(_TRIGGER_SQL):
            conn.execute(sa.text(statement))
        conn.execute(
            sa.text("INSERT INTO audit_head (id, seq, hash) VALUES (1, 0, :h) ON CONFLICT DO NOTHING"),
            {"h": GENESIS},
        )
        timescale_setup(conn)
        for role, tables in ROLE_GRANTS.items():
            password = (role_passwords or {}).get(role)
            if password is None:
                continue
            if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", password):
                raise ValueError(f"Password for {role} must be 8-128 letters, digits, _ or -")
            exists = conn.execute(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}
            ).first()
            verb = "ALTER" if exists else "CREATE"
            conn.execute(sa.text(f"{verb} ROLE {role} LOGIN PASSWORD '{password}'"))
            conn.execute(sa.text(f"GRANT USAGE ON SCHEMA public TO {role}"))
            conn.execute(sa.text(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}"))
            for table, privileges in tables.items():
                conn.execute(sa.text(f"GRANT {privileges} ON {table} TO {role}"))
            conn.execute(sa.text(
                f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"
            ))


def _split_plpgsql(sql: str) -> list[str]:
    """Split on semicolons that sit outside $$ bodies."""
    parts, buffer, inside = [], [], False
    for piece in re.split(r"(\$\$)", sql):
        if piece == "$$":
            inside = not inside
            buffer.append(piece)
            continue
        if inside:
            buffer.append(piece)
            continue
        segments = piece.split(";")
        for i, segment in enumerate(segments):
            buffer.append(segment)
            if i < len(segments) - 1:
                statement = "".join(buffer).strip()
                if statement:
                    parts.append(statement)
                buffer = []
    tail = "".join(buffer).strip()
    if tail:
        parts.append(tail)
    return parts


def role_passwords_from_env() -> dict[str, str]:
    out = {}
    for role in ROLE_GRANTS:
        value = os.environ.get(role.upper() + "_PASSWORD")
        if value:
            out[role] = value
    return out


@lru_cache
def get_engine() -> sa.Engine:
    return sa.create_engine(database_url(), pool_pre_ping=True, pool_size=5, max_overflow=5)
