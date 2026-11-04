"""Administrator commands. Run with the database owner's DATABASE_URL.

    python -m sentinel.admin migrate
    python -m sentinel.admin add-node chennai-1 --lat 13.08 --lon 80.27 --region "Chennai"
    python -m sentinel.admin verify-audit
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys

import sqlalchemy as sa

from .compliance import audit
from .db import get_engine, migrate, nodes, role_passwords_from_env


def add_node(args: argparse.Namespace) -> int:
    if args.lat is None or args.lon is None:
        print("Warning: without --lat and --lon this node cannot be matched to nearby hazards.", file=sys.stderr)
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with get_engine().begin() as conn:
        exists = conn.execute(sa.select(nodes.c.id).where(nodes.c.id == args.id)).first()
        if exists:
            conn.execute(nodes.update().where(nodes.c.id == args.id).values(
                token_hash=token_hash, lat=args.lat, lon=args.lon, region=args.region,
            ))
        else:
            conn.execute(nodes.insert().values(
                id=args.id, token_hash=token_hash, lat=args.lat, lon=args.lon, region=args.region,
            ))
        audit.append(conn, "node_token_issued", {"node": args.id, "rotated": bool(exists)})
    print(token)
    print("Store this token now, it is not shown again.", file=sys.stderr)
    return 0


def drill_hazard(args: argparse.Namespace) -> int:
    """Record a practice alert, clearly titled DRILL, through the same path as real feeds."""
    from datetime import datetime, timedelta, timezone

    from .hazards.feeds import ParsedHazard
    from .services.hazards import store

    now = datetime.now(timezone.utc)
    hazard = ParsedHazard(
        source="drill", external_id=f"drill-{secrets.token_hex(8)}", hazard_type=args.type,
        severity=args.severity, title=f"DRILL {args.type} alert", lat=args.lat, lon=args.lon,
        radius_km=args.radius_km, verified=True, starts_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1), raw={"drill": True},
    )
    with get_engine().begin() as conn:
        store(conn, [hazard])
    print(f"Recorded {hazard.title} at {args.lat}, {args.lon}. It expires in 1 hour.")
    return 0


def verify_audit(_: argparse.Namespace) -> int:
    with get_engine().connect() as conn:
        result = audit.verify(conn, os.environ.get("AUDIT_ANCHOR_PATH"))
    print(json.dumps({
        "ok": result.ok, "entries": result.entries, "log_batches": result.batches,
        "head": result.head_hash, "problems": result.problems,
    }, indent=2))
    return 0 if result.ok else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate").set_defaults(func=lambda _: (migrate(get_engine(), role_passwords_from_env()), 0)[1])
    node = sub.add_parser("add-node")
    node.add_argument("id")
    node.add_argument("--lat", type=float)
    node.add_argument("--lon", type=float)
    node.add_argument("--region")
    node.set_defaults(func=add_node)
    drill = sub.add_parser("drill-hazard")
    drill.add_argument("--lat", type=float, required=True)
    drill.add_argument("--lon", type=float, required=True)
    drill.add_argument("--type", default="earthquake")
    drill.add_argument("--severity", default="moderate", choices=["minor", "moderate", "severe", "extreme"])
    drill.add_argument("--radius-km", type=float, default=150.0)
    drill.set_defaults(func=drill_hazard)
    sub.add_parser("verify-audit").set_defaults(func=verify_audit)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
