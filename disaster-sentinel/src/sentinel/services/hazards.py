"""Poll external hazard feeds into the repository. A feed outage never stops other feeds."""
from __future__ import annotations

import logging
import os
import time
import urllib.request
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert

from ..compliance import audit
from ..config import Policy, policy
from ..db import get_engine, hazard_events, kv
from ..hazards.feeds import ParsedHazard, parse_cap, parse_sachet_rss, parse_usgs

log = logging.getLogger("sentinel.hazards")
MAX_BYTES = 8 * 1024 * 1024


def fetch(url: str, timeout: float = 20) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "disaster-sentinel/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"Feed larger than {MAX_BYTES} bytes: {url}")
    return data


def store(conn: sa.Connection, hazards: list[ParsedHazard]) -> int:
    new = 0
    for h in hazards:
        statement = insert(hazard_events).values(
            source=h.source, external_id=h.external_id, hazard_type=h.hazard_type,
            severity=h.severity, title=h.title, lat=h.lat, lon=h.lon, radius_km=h.radius_km,
            verified=h.verified, starts_at=h.starts_at, expires_at=h.expires_at, raw=h.raw,
        ).on_conflict_do_update(
            constraint="uq_hazard_source_ext",
            set_=dict(severity=h.severity, title=h.title, radius_km=h.radius_km, lat=h.lat, lon=h.lon,
                      expires_at=h.expires_at, raw=h.raw),
        ).returning(hazard_events.c.id, sa.text("(xmax = 0) AS inserted"))
        row = conn.execute(statement).one()
        if row.inserted:
            new += 1
            audit.append(conn, "hazard_recorded", {
                "id": row.id, "source": h.source, "external_id": h.external_id,
                "type": h.hazard_type, "severity": h.severity,
            })
    return new


def poll_usgs(pol: Policy, get=fetch) -> list[ParsedHazard]:
    return parse_usgs(get(pol.hazards.usgs_url), pol.hazards.usgs_min_magnitude, pol.hazards.hazard_ttl_h)


def poll_sachet(pol: Policy, known: set[str], get=fetch) -> tuple[list[ParsedHazard], set[str]]:
    items = parse_sachet_rss(get(pol.hazards.sachet_url))
    out, seen = [], set()
    for item in items:
        if item["id"] in known or len(seen) >= pol.hazards.sachet_max_cap_fetch:
            continue
        seen.add(item["id"])
        try:
            hazard = parse_cap(get(item["link"]), item, pol.hazards.hazard_ttl_h)
            if hazard:
                out.append(hazard)
        except Exception as exc:
            log.warning("Skipped SACHET alert %s: %s", item["id"], exc)
    return out, seen


def poll_once(engine: sa.Engine, pol: Policy, known: set[str], get=fetch) -> dict:
    status: dict = {"at": datetime.now(timezone.utc).isoformat()}
    for name, job in (("usgs", lambda: (poll_usgs(pol, get), set())),
                      ("sachet", lambda: poll_sachet(pol, known, get))):
        try:
            hazards, seen = job()
            with engine.begin() as conn:
                new = store(conn, hazards)
            known |= seen
            status[name] = {"ok": True, "parsed": len(hazards), "new": new}
        except Exception as exc:
            log.warning("%s feed failed: %s", name, exc)
            status[name] = {"ok": False, "error": str(exc)[:200]}
    with engine.begin() as conn:
        conn.execute(insert(kv).values(key="hazard_feeds", value=status).on_conflict_do_update(
            index_elements=["key"], set_={"value": status}))
    return status


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    engine, pol = get_engine(), policy()
    known: set[str] = set()
    while True:
        log.info("Polled feeds: %s", poll_once(engine, pol, known))
        time.sleep(float(os.environ.get("HAZARD_POLL_S", pol.hazards.poll_s)))


if __name__ == "__main__":
    main()
