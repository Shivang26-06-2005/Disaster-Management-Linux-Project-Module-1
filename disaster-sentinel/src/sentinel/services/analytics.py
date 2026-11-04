"""Identification and analytics worker (slide 12, step 2).

Reads new telemetry from the repository, runs detection and correlation, and writes
detections and incidents back. Only one replica does work at a time, through a
Postgres advisory lock, so extra replicas act as hot standbys (slide 4: high availability).
"""
from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa

from ..compliance import audit
from ..config import Policy, policy
from ..correlation.engine import Decision, Hazard, Node, Signal, evaluate
from ..db import detections, get_engine, hazard_events, incidents, ingest_batches, kv, log_events, metrics, nodes, recovery_actions
from ..detection.signatures import SignatureMatcher
from ..detection.zscore import ZScoreDetector

log = logging.getLogger("sentinel.analytics")
LOCK_ID = 7215001
BATCH = 5000
SEVERITY_ORDER = {"LOW": 0, "HIGH": 1}
# These need a person to close them. Faults that clear by themselves can auto-resolve.
HUMAN_CLOSE = {"cyber_breach", "brute_force", "system_critical", "hazard_infrastructure"}


class Analytics:
    def __init__(self, engine: sa.Engine, pol: Policy | None = None):
        self.engine = engine
        self.policy = pol or policy()
        self.detector = ZScoreDetector(self.policy.detection)
        self.matcher = SignatureMatcher(self.policy.signatures, self.policy.self_log_tags)
        self._seeded: set[str] = set()
        self._silent_flagged: dict[str, datetime] = {}

    def _seed(self, conn: sa.Connection, node_id: str) -> None:
        if node_id in self._seeded:
            return
        self._seeded.add(node_id)
        rows = conn.execute(
            sa.select(metrics.c.cpu, metrics.c.mem, metrics.c.disk)
            .where(metrics.c.node_id == node_id, metrics.c.processed)
            .order_by(metrics.c.ts.desc()).limit(self.policy.detection.window)
        ).all()
        for index, name in enumerate(("cpu", "mem", "disk")):
            values = [r[index] for r in reversed(rows) if r[index] is not None]
            self.detector.seed(node_id, name, values)

    def _detect_metrics(self, conn: sa.Connection) -> set[str]:
        rows = conn.execute(
            sa.select(metrics).where(~metrics.c.processed).order_by(metrics.c.ts).limit(BATCH)
        ).mappings().all()
        touched: set[str] = set()
        out = []
        for row in rows:
            self._seed(conn, row["node_id"])
            touched.add(row["node_id"])
            for name in ("cpu", "mem", "disk"):
                found = self.detector.observe(row["node_id"], name, row["ts"], row[name])
                if found:
                    out.append(dict(
                        ts=found.ts, node_id=found.node_id, modality="metric", name=name, strength="weak",
                        attrs={"value": found.value, "z": found.z, "mean": found.mean, "std": found.std,
                               "reason": found.reason, "duration_s": found.duration_s},
                    ))
        if rows:
            conn.execute(metrics.update().where(metrics.c.id.in_([r["id"] for r in rows])).values(processed=True))
        if out:
            conn.execute(detections.insert(), out)
        return touched

    def _detect_logs(self, conn: sa.Connection) -> set[str]:
        rows = conn.execute(
            sa.select(log_events).where(~log_events.c.processed).order_by(log_events.c.id).limit(BATCH)
        ).mappings().all()
        touched: set[str] = set()
        out = []
        for row in rows:
            touched.add(row["node_id"])
            for match in self.matcher.match(row["line"]):
                out.append(dict(
                    ts=row["ts"], node_id=row["node_id"], modality="log", name=match.class_,
                    strength=match.strength,
                    attrs={**match.attrs, "signature": match.name, "source": row["source"], "log_id": row["id"]},
                ))
        if rows:
            conn.execute(log_events.update().where(log_events.c.id.in_([r["id"] for r in rows])).values(processed=True))
        if out:
            conn.execute(detections.insert(), out)
        return touched

    def _detect_silence(self, conn: sa.Connection, now: datetime) -> set[str]:
        limit = timedelta(seconds=self.policy.correlation.heartbeat_silent_s)
        touched = set()
        for row in conn.execute(sa.select(nodes.c.id, nodes.c.last_seen).where(nodes.c.last_seen.is_not(None))):
            if now - row.last_seen > limit:
                touched.add(row.id)
                flagged = self._silent_flagged.get(row.id)
                if flagged is None or now - flagged > timedelta(seconds=self.policy.correlation.window_s / 2):
                    self._silent_flagged[row.id] = now
                    conn.execute(detections.insert().values(
                        ts=now, node_id=row.id, modality="heartbeat", name="silent", strength="weak",
                        attrs={"last_seen": row.last_seen.isoformat()},
                    ))
            else:
                self._silent_flagged.pop(row.id, None)
        return touched

    def _hazards(self, conn: sa.Connection, now: datetime) -> list[Hazard]:
        rows = conn.execute(sa.select(hazard_events).where(
            hazard_events.c.expires_at >= now, hazard_events.c.starts_at <= now
        )).mappings().all()
        return [Hazard(
            id=r["id"], source=r["source"], hazard_type=r["hazard_type"], severity=r["severity"],
            title=r["title"], lat=r["lat"], lon=r["lon"], radius_km=r["radius_km"],
            verified=r["verified"], starts_at=r["starts_at"], expires_at=r["expires_at"],
        ) for r in rows]

    def _apply(self, conn: sa.Connection, node_id: str, d: Decision, now: datetime) -> None:
        pb = self.policy.playbooks.get(d.category)
        existing = conn.execute(sa.select(incidents).where(
            incidents.c.node_id == node_id, incidents.c.category == d.category,
            incidents.c.status == "open",
        ).with_for_update()).mappings().first()

        if existing is None:
            certin = pb.certin_type if pb and d.severity == "HIGH" else None
            hours = self.policy.compliance.report_deadline_hours
            row = conn.execute(incidents.insert().values(
                node_id=node_id, category=d.category, severity=d.severity, status="open",
                title=d.title, summary=d.summary, reasons=d.reasons, attrs=d.attrs,
                hazard_ids=d.hazard_ids, noticed_at=now, last_signal_at=now,
                certin_type=certin,
                certin_deadline=now + timedelta(hours=hours) if certin else None,
            ).returning(incidents.c.id)).one()
            audit.append(conn, "incident_opened", {
                "incident": row.id, "node": node_id, "category": d.category, "severity": d.severity,
                "reasons": d.reasons, "certin_type": certin,
            }, now)
            return

        values: dict = {"last_signal_at": now, "reasons": d.reasons, "summary": d.summary,
                        "title": d.title, "attrs": {**existing["attrs"], **d.attrs},
                        "hazard_ids": d.hazard_ids or existing["hazard_ids"]}
        if SEVERITY_ORDER[d.severity] > SEVERITY_ORDER[existing["severity"]]:
            certin = pb.certin_type if pb else None
            hours = self.policy.compliance.report_deadline_hours
            values.update(
                severity=d.severity, certin_type=certin,
                certin_deadline=now + timedelta(hours=hours) if certin else None,
            )
            audit.append(conn, "incident_escalated", {
                "incident": existing["id"], "from": existing["severity"], "to": d.severity,
                "reasons": d.reasons,
            }, now)
        conn.execute(incidents.update().where(incidents.c.id == existing["id"]).values(**values))

    def _auto_resolve(self, conn: sa.Connection, now: datetime) -> None:
        quiet = now - timedelta(seconds=self.policy.correlation.auto_resolve_s)
        rows = conn.execute(sa.select(incidents).where(
            incidents.c.status == "open", incidents.c.last_signal_at < quiet,
        )).mappings().all()
        for row in rows:
            if row["category"] in HUMAN_CLOSE and row["severity"] == "HIGH":
                continue
            busy = conn.execute(sa.select(recovery_actions.c.id).where(
                recovery_actions.c.incident_id == row["id"],
                recovery_actions.c.status.in_(("pending", "claimed", "awaiting_approval")),
            )).first()
            if busy:
                continue
            conn.execute(incidents.update().where(incidents.c.id == row["id"]).values(
                status="resolved", resolved_at=now, resolved_by="auto",
            ))
            audit.append(conn, "incident_auto_resolved", {"incident": row["id"], "node": row["node_id"]}, now)

    def tick(self, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        with self.engine.begin() as conn:
            touched = self._detect_metrics(conn) | self._detect_logs(conn) | self._detect_silence(conn, now)
            hazards = self._hazards(conn, now)
            all_nodes = {r["id"]: r for r in conn.execute(sa.select(nodes)).mappings()}
            # A hazard can make any located node relevant even when its telemetry is quiet.
            targets = set(all_nodes) if hazards else touched

            window_start = now - timedelta(seconds=self.policy.correlation.window_s)
            signals_by_node: dict[str, list[Signal]] = defaultdict(list)
            for row in conn.execute(sa.select(detections).where(detections.c.ts >= window_start)).mappings():
                signals_by_node[row["node_id"]].append(Signal(
                    ts=row["ts"], modality=row["modality"], name=row["name"],
                    strength=row["strength"], attrs=row["attrs"],
                ))
                targets.add(row["node_id"])

            made = 0
            for node_id in targets:
                record = all_nodes.get(node_id)
                node = Node(node_id, record["lat"] if record else None, record["lon"] if record else None)
                for decision in evaluate(node, signals_by_node.get(node_id, []), hazards, now, self.policy.correlation):
                    self._apply(conn, node_id, decision, now)
                    made += 1
            self._auto_resolve(conn, now)
        return made

    def housekeeping(self, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        horizon = now - timedelta(days=self.policy.compliance.retention_days)
        with self.engine.begin() as conn:
            removed = 0
            for table in (metrics, log_events):
                removed += conn.execute(table.delete().where(table.c.ts < horizon)).rowcount or 0
            conn.execute(detections.delete().where(detections.c.ts < horizon))
            conn.execute(ingest_batches.delete().where(ingest_batches.c.received_at < horizon))
            if removed:
                audit.append(conn, "retention_purge", {"rows": removed, "older_than": horizon.isoformat()}, now)
            anchor_path = os.environ.get("AUDIT_ANCHOR_PATH")
            if anchor_path:
                audit.write_anchor(conn, anchor_path)


def record_profile(engine: sa.Engine, pol: Policy) -> None:
    """Audit each change of the policy profile, so behaviour changes leave a trace."""
    with engine.begin() as conn:
        current = conn.execute(sa.select(kv.c.value).where(kv.c.key == "policy")).scalar()
        if not current or current.get("digest") != pol.digest:
            value = {"digest": pol.digest, "version": pol.profile_version}
            audit.append(conn, "policy_loaded", value)
            statement = sa.dialects.postgresql.insert(kv).values(key="policy", value=value)
            conn.execute(statement.on_conflict_do_update(index_elements=["key"], set_={"value": value}))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    engine, pol = get_engine(), policy()
    worker = Analytics(engine, pol)
    interval = float(os.environ.get("ANALYTICS_INTERVAL_S", "5"))
    lock = engine.connect()
    while not lock.execute(sa.text("SELECT pg_try_advisory_lock(:i)"), {"i": LOCK_ID}).scalar():
        lock.rollback()
        log.info("Another analytics replica is active. Standing by.")
        time.sleep(10)
    lock.commit()
    log.info("Analytics active with profile %s", pol.profile_version)
    record_profile(engine, pol)
    last_housekeeping = 0.0
    while True:
        try:
            worker.tick()
            if time.time() - last_housekeeping > pol.compliance.anchor_every_s:
                worker.housekeeping()
                last_housekeeping = time.time()
        except Exception:
            log.exception("Analytics tick failed, retrying")
        time.sleep(interval)


if __name__ == "__main__":
    main()
