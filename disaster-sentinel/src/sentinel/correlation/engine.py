"""Multi-Modal Telemetry Correlation Engine (slide 10, the proposed contribution).

Pure logic with no I/O, so every rule can be unit tested and every decision can
state its reasons in plain language.

Three properties matter more than the individual rules:

1. Correlation never suppresses a hard security or hardware signal. A breach is
   HIGH whether or not an earthquake is nearby.
2. A weak signal alone stays LOW. It needs a second modality, a repeat, or a
   nearby verified hazard before anything acts on it. This is where false
   positives are removed.
3. Unverified citizen reports are context only. They can never raise severity,
   otherwise anyone could trigger recovery by posting a message.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..config import Correlation

SEVERITY_RANK = {"unknown": 0, "minor": 1, "moderate": 2, "severe": 3, "extreme": 4}
# Operators see what happened, not the name of the rule that noticed it (slide 6).
SIGNATURE_TEXT = {
    "breach_keyword": "The logs report a security breach",
    "breakin_attempt": "The logs report a possible break-in attempt",
    "rootkit_warning": "A rootkit warning appeared in the logs",
    "critical_keyword": "The logs report a critical error",
    "kernel_panic": "The kernel reported a panic",
    "oom_kill": "The system ran out of memory and killed a process",
    "disk_io_error": "The disk reported read or write errors",
    "hardware_error": "The hardware reported an error",
}


@dataclass(frozen=True)
class Signal:
    ts: datetime
    modality: str   # "metric", "log" or "heartbeat"
    name: str       # metric name or signature class
    strength: str   # "hard" or "weak"
    attrs: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Hazard:
    id: int
    source: str
    hazard_type: str
    severity: str
    title: str
    lat: float | None
    lon: float | None
    radius_km: float
    verified: bool
    starts_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class Node:
    id: str
    lat: float | None = None
    lon: float | None = None


@dataclass
class Decision:
    category: str
    severity: str           # "LOW" or "HIGH"
    title: str
    summary: str
    reasons: list[str]
    attrs: dict = field(default_factory=dict)
    hazard_ids: list[int] = field(default_factory=list)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def nearby_hazards(node: Node, hazards: list[Hazard], now: datetime) -> list[tuple[Hazard, float]]:
    if node.lat is None or node.lon is None:
        return []
    near = []
    for h in hazards:
        if h.lat is None or h.lon is None or not (h.starts_at <= now <= h.expires_at):
            continue
        distance = haversine_km(node.lat, node.lon, h.lat, h.lon)
        if distance <= h.radius_km:
            near.append((h, distance))
    return sorted(near, key=lambda pair: (-SEVERITY_RANK.get(pair[0].severity, 0), pair[1]))


def _describe_metric(s: Signal) -> str:
    label = {"cpu": "CPU", "mem": "memory", "disk": "disk"}.get(s.name, s.name)
    value = s.attrs.get("value")
    return f"{label} at {value:.0f}%" if isinstance(value, (int, float)) else f"{label} unusually high"


def evaluate(
    node: Node,
    signals: list[Signal],
    hazards: list[Hazard],
    now: datetime,
    cfg: Correlation,
) -> list[Decision]:
    window = timedelta(seconds=cfg.window_s)
    recent = [s for s in signals if now - window <= s.ts <= now]
    near = nearby_hazards(node, hazards, now)
    official = [(h, d) for h, d in near if h.verified]
    unverified = [(h, d) for h, d in near if not h.verified]
    context = [
        f"Unverified public report nearby ({d:.0f} km): {h.title}. Shown for context only."
        for h, d in unverified[:3]
    ]

    metrics = [s for s in recent if s.modality == "metric"]
    logs = [s for s in recent if s.modality == "log"]
    silent = [s for s in recent if s.modality == "heartbeat"]
    by_class: dict[str, list[Signal]] = defaultdict(list)
    for s in logs:
        by_class[s.name].append(s)

    decisions: list[Decision] = []
    handled_weak: set[str] = set()

    def hazard_reasons() -> list[str]:
        return [
            f"Official {h.source.upper()} alert {d:.0f} km away: {h.title}" for h, d in official[:3]
        ]

    # Rule 1. Hard security signals are never downgraded.
    if by_class["breach"]:
        s = by_class["breach"][-1]
        decisions.append(Decision(
            "cyber_breach", "HIGH", "Possible security breach",
            "The system logged a security breach signature. Evidence is being preserved and "
            "the response team has been told.",
            [SIGNATURE_TEXT.get(s.attrs.get("signature"), "The logs report a security problem"), *hazard_reasons(), *context],
            {"signature": s.attrs.get("signature")},
        ))

    # Rule 2. Repeated failed logins from a single address.
    per_ip: Counter[str] = Counter(
        s.attrs["ip"] for s in by_class["auth_failed"] if s.attrs.get("ip")
    )
    if per_ip:
        ip, count = per_ip.most_common(1)[0]
        if count >= cfg.brute_force_count:
            handled_weak.add("auth_failed")
            decisions.append(Decision(
                "brute_force", "HIGH", f"Repeated failed logins from {ip}",
                f"{count} failed logins came from {ip} in the last "
                f"{cfg.window_s // 60} minutes.",
                [f"{count} failed logins from one address, limit is {cfg.brute_force_count}", *context],
                {"ip": ip, "count": count},
            ))

    # Rule 3. Hard system signals: panics, OOM kills, disk I/O errors.
    if by_class["critical"]:
        s = by_class["critical"][-1]
        reasons = [SIGNATURE_TEXT.get(s.attrs.get("signature"), "The logs report a critical fault")]
        reasons += hazard_reasons() + context
        summary = "The system logged a critical fault. A backup is being taken."
        if official:
            summary = f"A critical fault was logged while {official[0][0].title} is active nearby."
        decisions.append(Decision(
            "system_critical", "HIGH", "Critical system fault", summary, reasons,
            {"signature": s.attrs.get("signature")}, [h.id for h, _ in official],
        ))

    weak_failed = by_class["failed"]
    weak_auth = [] if "auth_failed" in handled_weak else by_class["auth_failed"]
    weak_present = bool(metrics or weak_failed or weak_auth or silent)

    # Rule 4. Any weak infrastructure signal plus a verified nearby hazard.
    if official and weak_present:
        h, d = official[0]
        parts = []
        if metrics:
            parts.append(_describe_metric(metrics[-1]))
        if weak_failed:
            parts.append("service failures in the logs")
        if silent:
            parts.append("the node stopped reporting")
        if weak_auth:
            parts.append("failed logins")
        decisions.append(Decision(
            "hazard_infrastructure", "HIGH",
            f"{h.hazard_type.capitalize()} may be affecting this node",
            f"{h.title} is {d:.0f} km away and this node shows {', '.join(parts)}.",
            [*hazard_reasons(), *[f"Infrastructure signal: {p}" for p in parts], *context],
            {"hazard_type": h.hazard_type, "distance_km": round(d, 1)},
            [h.id for h, _ in official],
        ))
        return decisions

    # Rule 5. Two modalities close together: a metric anomaly and a failed service.
    corroboration = timedelta(seconds=cfg.corroboration_s)
    paired = [
        (m, f) for m in metrics for f in weak_failed if abs(m.ts - f.ts) <= corroboration
    ]
    service_counts: Counter[str] = Counter(
        s.attrs["service"] for s in weak_failed if s.attrs.get("service")
    )
    if paired:
        m, f = paired[-1]
        service = f.attrs.get("service") or (service_counts.most_common(1)[0][0] if service_counts else None)
        reasons = [
            f"{_describe_metric(m).capitalize()} and a logged failure"
            f"{' of ' + service if service else ''} within {cfg.corroboration_s // 60} minutes",
            *context,
        ]
        if service:
            decisions.append(Decision(
                "service_failure", "HIGH", f"{service} failed under load",
                f"{service} failed while {_describe_metric(m)}. Restarting it.",
                reasons, {"service": service},
            ))
        else:
            decisions.append(Decision(
                "resource_exhaustion", "HIGH", "System under abnormal load",
                f"{_describe_metric(m).capitalize()} alongside logged failures.",
                reasons, {"metric": m.name},
            ))
        handled_weak.update({"failed", "metric"})

    # Rule 6. A metric anomaly that lasts, or that sits at the hard ceiling.
    if "metric" not in handled_weak:
        lasting = [
            m for m in metrics
            if m.attrs.get("duration_s", 0) >= cfg.sustained_s or m.attrs.get("reason") == "ceiling"
        ]
        if lasting:
            m = lasting[-1]
            decisions.append(Decision(
                "resource_exhaustion", "HIGH", f"{_describe_metric(m).capitalize()}",
                f"{_describe_metric(m).capitalize()} has stayed abnormal. Clearing caches.",
                [f"Abnormal for {m.attrs.get('duration_s', 0):.0f} seconds"
                 if m.attrs.get("reason") != "ceiling" else "Reached the hard limit", *context],
                {"metric": m.name},
            ))
            handled_weak.add("metric")

    # Rule 7. The same service failing repeatedly.
    if "failed" not in handled_weak and service_counts:
        service, count = service_counts.most_common(1)[0]
        if count >= cfg.service_failed_count:
            decisions.append(Decision(
                "service_failure", "HIGH", f"{service} keeps failing",
                f"{service} failed {count} times in {cfg.window_s // 60} minutes. Restarting it.",
                [f"{count} failures of one service, limit is {cfg.service_failed_count}", *context],
                {"service": service},
            ))
            handled_weak.add("failed")

    # Rule 8. A serious verified hazard with no local symptoms yet.
    watch_rank = SEVERITY_RANK[cfg.hazard_watch_severity]
    if official:
        h, d = official[0]
        high = SEVERITY_RANK.get(h.severity, 0) >= watch_rank
        decisions.append(Decision(
            "hazard_watch", "HIGH" if high else "LOW",
            f"{h.hazard_type.capitalize()} alert near this node",
            f"{h.title} is {d:.0f} km away. This node is healthy so far."
            + (" Taking a precautionary backup." if high else ""),
            hazard_reasons(), {"hazard_type": h.hazard_type, "distance_km": round(d, 1)},
            [h.id for h, _ in official],
        ))

    # Rule 9. Everything else is an isolated weak signal: record it and take no action.
    leftovers: list[str] = []
    if metrics and "metric" not in handled_weak:
        leftovers.append(_describe_metric(metrics[-1]))
    if weak_failed and "failed" not in handled_weak:
        leftovers.append("a logged service failure")
    if weak_auth:
        leftovers.append("failed logins")
    if silent:
        leftovers.append("the node stopped reporting")
    if leftovers:
        decisions.append(Decision(
            "isolated_signal", "LOW", "Brief unusual activity",
            f"Noted {', '.join(leftovers)}. Nothing else supports a problem, so no action was taken.",
            [f"Single signal: {x}" for x in leftovers] + context,
        ))
    return decisions
