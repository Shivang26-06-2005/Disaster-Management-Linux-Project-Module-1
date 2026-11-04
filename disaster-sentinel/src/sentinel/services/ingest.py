"""Telemetry ingestion API for edge agents (slide 10, technique 3; slide 13, model 4).

Agents authenticate with a per-node bearer token and only ever connect outbound.
Batches carry an ID so a retry after a network failure cannot create duplicates.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

import sqlalchemy as sa
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from ..compliance import audit
from ..config import policy
from ..db import get_engine, ingest_batches, log_events, metrics, nodes, recovery_actions

log = logging.getLogger("sentinel.ingest")
app = FastAPI(title="Disaster Sentinel ingest", docs_url=None, redoc_url=None, openapi_url=None)

MAX_BODY = 4 * 1024 * 1024
MAX_FUTURE = timedelta(minutes=5)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class MetricSample(BaseModel):
    ts: datetime
    cpu: float | None = Field(default=None, ge=0, le=100)
    mem: float | None = Field(default=None, ge=0, le=100)
    disk: float | None = Field(default=None, ge=0, le=100)
    load1: float | None = Field(default=None, ge=0)


class LogLine(BaseModel):
    ts: datetime
    source: str = Field(max_length=120)
    line: str = Field(max_length=8192)

    @field_validator("line", "source")
    @classmethod
    def no_nul(cls, value: str) -> str:
        return value.replace("\x00", "")  # PostgreSQL text cannot hold NUL bytes


class AgentStatus(BaseModel):
    version: str = Field(default="", max_length=32)
    hostname: str = Field(default="", max_length=255)
    mode: str = Field(default="dry_run", max_length=16)
    recovery_ready: bool = False
    ntp_synced: bool | None = None
    spooled: int = 0
    dropped: int = 0
    sources: list[str] = Field(default_factory=list, max_length=20)
    self_cpu: float | None = None
    self_rss_mb: float | None = None


class Batch(BaseModel):
    batch_id: uuid.UUID
    sent_at: datetime
    status: AgentStatus = Field(default_factory=AgentStatus)
    metrics: list[MetricSample] = Field(default_factory=list, max_length=20000)
    logs: list[LogLine] = Field(default_factory=list, max_length=20000)

    @field_validator("sent_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class ActionResult(BaseModel):
    exit_code: int
    dry_run: bool
    output: str = Field(default="", max_length=20000)


def current_node(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token_hash = hash_token(authorization.removeprefix("Bearer ").strip())
    with get_engine().connect() as conn:
        row = conn.execute(sa.select(nodes.c.id, nodes.c.token_hash).where(nodes.c.token_hash == token_hash)).first()
    if row is None or not hmac.compare_digest(row.token_hash, token_hash):
        raise HTTPException(401, "Unknown node token")
    return {"id": row.id}


def _clean_ts(ts: datetime, now: datetime) -> datetime:
    """A wrong agent clock must not write the future into the time series."""
    ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return now if ts > now + MAX_FUTURE else ts


@app.middleware("http")
async def limit_body(request: Request, call_next):
    length = request.headers.get("content-length")
    if length and int(length) > MAX_BODY:
        from fastapi.responses import JSONResponse

        return JSONResponse({"detail": "Batch too large"}, status_code=413)
    return await call_next(request)


@app.get("/healthz")
def healthz() -> dict:
    with get_engine().connect() as conn:
        conn.execute(sa.text("SELECT 1"))
    return {"ok": True}


@app.post("/v1/telemetry")
def telemetry(batch: Batch, node: Annotated[dict, Depends(current_node)]) -> dict:
    now = datetime.now(timezone.utc)
    batch_id = str(batch.batch_id)
    skew = (now - batch.sent_at).total_seconds()
    with get_engine().begin() as conn:
        duplicate = conn.execute(
            sa.select(ingest_batches.c.batch_id).where(ingest_batches.c.batch_id == batch_id)
        ).first()
        if duplicate:
            return {"accepted": False, "duplicate": True, "server_time": now.isoformat()}
        conn.execute(ingest_batches.insert().inline().values(batch_id=batch_id, node_id=node["id"]))
        if batch.metrics:
            conn.execute(metrics.insert().inline(), [
                dict(ts=_clean_ts(m.ts, now), node_id=node["id"], cpu=m.cpu, mem=m.mem, disk=m.disk, load1=m.load1)
                for m in batch.metrics
            ])
        if batch.logs:
            rows = [
                dict(ts=_clean_ts(l.ts, now), node_id=node["id"], batch_id=batch_id, seq=i,
                     source=l.source, line=l.line)
                for i, l in enumerate(batch.logs)
            ]
            conn.execute(log_events.insert().inline(), rows)
            audit.append(conn, "log_batch", {
                "batch_id": batch_id, "node": node["id"], "count": len(rows),
                "sha256": audit.batch_digest([(r["seq"], r["source"], r["line"]) for r in rows]),
            }, now)
        conn.execute(nodes.update().where(nodes.c.id == node["id"]).values(
            last_seen=now, clock_skew_s=round(skew, 3), hostname=batch.status.hostname or None,
            agent=batch.status.model_dump(),
        ))
    return {"accepted": True, "server_time": now.isoformat(),
            "clock_skew_ok": abs(skew) <= policy().compliance.max_clock_skew_s}


@app.post("/v1/actions/claim")
def claim(node: Annotated[dict, Depends(current_node)]) -> dict:
    """Hand the node its pending actions. Row locks stop an action being claimed twice."""
    now = datetime.now(timezone.utc)
    with get_engine().begin() as conn:
        rows = conn.execute(sa.select(recovery_actions).where(
            recovery_actions.c.node_id == node["id"], recovery_actions.c.status == "pending",
            recovery_actions.c.expires_at >= now,
        ).order_by(recovery_actions.c.id).limit(10).with_for_update(skip_locked=True)).mappings().all()
        out = []
        for row in rows:
            conn.execute(recovery_actions.update().where(recovery_actions.c.id == row["id"]).values(
                status="claimed", claimed_at=now,
            ))
            audit.append(conn, "recovery_claimed", {"action_id": row["id"], "node": node["id"]}, now)
            out.append({"id": row["id"], "action": row["action"], "arg": row["arg"]})
    return {"actions": out}


@app.post("/v1/actions/{action_id}/result")
def result(action_id: int, body: ActionResult, node: Annotated[dict, Depends(current_node)]) -> dict:
    now = datetime.now(timezone.utc)
    with get_engine().begin() as conn:
        row = conn.execute(sa.select(recovery_actions).where(
            recovery_actions.c.id == action_id, recovery_actions.c.node_id == node["id"],
        ).with_for_update()).mappings().first()
        if row is None:
            raise HTTPException(404, "No such action for this node")
        if row["status"] != "claimed":
            return {"accepted": False, "status": row["status"]}
        status = "done" if body.exit_code == 0 else "failed"
        output = body.output.replace("\x00", "")
        conn.execute(recovery_actions.update().where(recovery_actions.c.id == action_id).values(
            status=status, finished_at=now, exit_code=body.exit_code, dry_run=body.dry_run, output=output,
        ))
        audit.append(conn, "recovery_finished", {
            "action_id": action_id, "incident": row["incident_id"], "node": node["id"],
            "action": row["action"], "arg": row["arg"], "status": status,
            "exit_code": body.exit_code, "dry_run": body.dry_run,
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        }, now)
    return {"accepted": True, "status": status}
