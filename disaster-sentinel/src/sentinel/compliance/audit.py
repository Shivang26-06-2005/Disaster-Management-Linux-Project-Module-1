"""Tamper-evident record keeping (slide 4 NFR 2, slide 12 "immutable data store").

Each entry stores HMAC(key, prev_hash + entry). Three layers back each other up:

* A database trigger rejects UPDATE, DELETE and TRUNCATE on audit_log.
* The HMAC key lives outside the database, so someone who can write to the
  database still cannot forge a valid chain.
* Periodic anchors are written outside the database, so cutting entries off the
  end of the chain, which a chain alone cannot reveal, is detected as well.

An attacker holding the database superuser, the HMAC key and the anchor volume
could still rewrite history. Keep the key and the anchors on separate systems in
a real deployment.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa

from ..config import env
from ..db import GENESIS, audit_head, audit_log, ingest_batches, log_events


def _key() -> bytes:
    key = env("AUDIT_HMAC_KEY")
    if len(key) < 32:
        raise RuntimeError("AUDIT_HMAC_KEY must be at least 32 characters")
    return key.encode()


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(prev_hash: str, seq: int, ts: datetime, kind: str, payload: str) -> str:
    message = f"{prev_hash}|{seq}|{ts.astimezone(timezone.utc).isoformat()}|{kind}|{payload}"
    return hmac.new(_key(), message.encode(), hashlib.sha256).hexdigest()


def append(conn: sa.Connection, kind: str, payload: dict, now: datetime | None = None) -> int:
    """Append inside the caller's transaction.

    The row lock on audit_head serialises writers, so the chain can never fork,
    and a rolled-back transaction leaves no audit entry for something that did
    not happen.
    """
    ts = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    head = conn.execute(
        sa.select(audit_head.c.seq, audit_head.c.hash).where(audit_head.c.id == 1).with_for_update()
    ).one()
    seq = head.seq + 1
    body = canonical(payload)
    digest = entry_hash(head.hash, seq, ts, kind, body)
    conn.execute(audit_log.insert().values(
        seq=seq, ts=ts, kind=kind, payload=body, prev_hash=head.hash, hash=digest,
    ))
    conn.execute(audit_head.update().where(audit_head.c.id == 1).values(seq=seq, hash=digest))
    return seq


def batch_digest(lines: list[tuple[int, str, str]]) -> str:
    """Hash a log batch from (seq, source, line) so stored logs can be re-checked later."""
    h = hashlib.sha256()
    for seq, source, line in sorted(lines):
        h.update(f"{seq}\x00{source}\x00{line}\n".encode("utf-8", "surrogateescape"))
    return h.hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    entries: int = 0
    batches: int = 0
    head_seq: int = 0
    head_hash: str = GENESIS
    problems: list[str] = field(default_factory=list)


def verify(conn: sa.Connection, anchor_path: str | None = None, check_logs: bool = True,
           log_horizon: datetime | None = None) -> VerifyResult:
    result = VerifyResult(ok=True)
    expected_prev, expected_seq = GENESIS, 1
    batches: dict[str, str] = {}

    rows = conn.execution_options(yield_per=2000).execute(
        sa.select(audit_log).order_by(audit_log.c.seq)
    )
    for row in rows:
        if row.seq != expected_seq:
            result.problems.append(f"Entry {expected_seq} is missing (next found is {row.seq})")
            expected_seq = row.seq
        if row.prev_hash != expected_prev:
            result.problems.append(f"Entry {row.seq} does not link to the entry before it")
        if entry_hash(row.prev_hash, row.seq, row.ts, row.kind, row.payload) != row.hash:
            result.problems.append(f"Entry {row.seq} was altered: its signature does not match")
        expected_prev, expected_seq = row.hash, row.seq + 1
        result.entries += 1
        if row.kind == "log_batch":
            payload = json.loads(row.payload)
            if log_horizon is None or row.ts >= log_horizon:
                batches[payload["batch_id"]] = payload["sha256"]

    head = conn.execute(sa.select(audit_head).where(audit_head.c.id == 1)).one()
    result.head_seq, result.head_hash = head.seq, head.hash
    if head.seq != expected_seq - 1 or head.hash != expected_prev:
        result.problems.append("The chain head does not match the last entry")

    if check_logs:
        grouped: dict[str, list[tuple[int, str, str]]] = {b: [] for b in batches}
        stream = conn.execution_options(yield_per=5000).execute(
            sa.select(log_events.c.batch_id, log_events.c.seq, log_events.c.source, log_events.c.line)
        )
        for r in stream:
            if r.batch_id in grouped:
                grouped[r.batch_id].append((r.seq, r.source, r.line))
        for batch_id, expected in batches.items():
            result.batches += 1
            if batch_digest(grouped[batch_id]) != expected:
                result.problems.append(f"Stored log batch {batch_id} was changed after it arrived")

    if anchor_path and Path(anchor_path).exists():
        by_seq = {}
        lines = Path(anchor_path).read_text().splitlines()
        wanted = [json.loads(l) for l in lines if l.strip()]
        if wanted:
            for r in conn.execute(sa.select(audit_log.c.seq, audit_log.c.hash).where(
                audit_log.c.seq.in_([a["seq"] for a in wanted])
            )):
                by_seq[r.seq] = r.hash
            for a in wanted:
                if by_seq.get(a["seq"]) != a["hash"]:
                    result.problems.append(
                        f"Anchor at entry {a['seq']} from {a['ts']} no longer matches the database"
                    )
    result.ok = not result.problems
    return result


def write_anchor(conn: sa.Connection, anchor_path: str) -> dict | None:
    head = conn.execute(sa.select(audit_head).where(audit_head.c.id == 1)).one()
    if head.seq == 0:
        return None
    anchor = {"seq": head.seq, "hash": head.hash, "ts": datetime.now(timezone.utc).isoformat()}
    path = Path(anchor_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(anchor) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return anchor
