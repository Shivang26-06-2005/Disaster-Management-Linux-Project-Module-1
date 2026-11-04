"""Baseline versus correlation engine on simulated scenarios (slide 16: "evaluate").

    python eval/correlation_eval.py --seeds 30

Baseline: the siloed approach slide 5 criticises. Every z-score anomaly and every log
signature raises its own alert, with repeats merged per signal for 10 minutes.
Proposed: the correlation engine. An alert is a HIGH incident, one per category.

The data is SIMULATED and the scenarios were written by the same person as the rules,
so this checks the logic and shows the trade-off. It is not field performance. The
"subtle" incidents are included on purpose because correlation should miss some.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinel.config import load_policy
from sentinel.correlation.engine import Hazard, Node, Signal, evaluate
from sentinel.detection.signatures import SignatureMatcher
from sentinel.detection.zscore import ZScoreDetector

ROOT = Path(__file__).resolve().parents[1]
STEP = 5
HOURS = 12
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
NODE = Node("sim", 13.08, 80.27)
BENIGN_LINES = [
    "CRON[811]: (root) CMD (run-parts /etc/cron.hourly)",
    "systemd[1]: Started Session 42 of user admin.",
    "kernel: [1234.5] eth0: link up",
    "sshd[77]: Accepted publickey for admin from 10.0.0.5 port 50022",
    "app[12]: scan finished, no critical findings",
    "app[12]: health check ok, 0 FAILED",
]


@dataclass
class Injected:
    kind: str
    start: int
    end: int
    real: bool


def scenario(rng: random.Random) -> tuple[list[dict], list[Injected], list[Hazard]]:
    n = HOURS * 3600 // STEP
    cpu_base, mem_base = rng.uniform(10, 45), rng.uniform(30, 60)
    ticks = [{"cpu": cpu_base, "mem": mem_base, "disk": 55.0, "lines": []} for _ in range(n)]
    cpu = cpu_base
    for t in ticks:
        cpu += (cpu_base - cpu) * 0.1 + rng.gauss(0, 2.5)
        t["cpu"] = min(max(cpu, 0), 100)
        t["mem"] = mem_base + rng.gauss(0, 0.8)
        if rng.random() < 0.03:
            t["lines"].append(rng.choice(BENIGN_LINES))

    injected: list[Injected] = []
    hazards: list[Hazard] = []

    def place(duration_s: int) -> int:
        return rng.randrange(1800 // STEP, n - (duration_s + 1800) // STEP)

    def bump(key: str, start: int, seconds: int, value: float) -> None:
        for i in range(start, start + seconds // STEP):
            ticks[i][key] = value + rng.gauss(0, 1.5)

    # Harmless events: what a siloed system pages people about.
    for _ in range(rng.randint(6, 10)):
        kind = rng.choice(["cron_spike", "stray_failed", "few_logins", "batch_memory"])
        if kind == "cron_spike":
            s = place(200)
            bump("cpu", s, rng.randint(40, 180), rng.uniform(82, 94))
        elif kind == "stray_failed":
            s = place(10)
            ticks[s]["lines"].append("systemd[1]: Failed to start motd-news.service")
        elif kind == "few_logins":
            s = place(60)
            for k in range(rng.randint(1, 3)):
                ticks[s + k]["lines"].append("sshd[7]: Failed password for root from 198.51.100.7 port 22 ssh2")
        else:
            s = place(200)
            bump("mem", s, rng.randint(60, 200), rng.uniform(84, 92))
        injected.append(Injected(kind, s, s + 40, False))

    # A verified but distant alert that should change nothing.
    hazards.append(Hazard(1, "usgs", "earthquake", "severe", "M 6.2 far away", 28.6, 77.2, 200, True,
                          T0, T0 + timedelta(hours=HOURS)))

    # Real incidents.
    for kind in rng.sample(["outage", "exhaustion", "brute", "breach", "quake_damage", "panic"], k=3):
        s = place(900)
        if kind == "outage":
            bump("cpu", s, 240, 92)
            for k in range(3):
                ticks[s + 6 + k * 12]["lines"].append("systemd[1]: nginx.service: Failed with result 'exit-code'.")
        elif kind == "exhaustion":
            bump("mem", s, 600, 97)
        elif kind == "brute":
            for k in range(20):
                ticks[s + k]["lines"].append("sshd[7]: Failed password for root from 203.0.113.9 port 22 ssh2")
        elif kind == "breach":
            ticks[s]["lines"].append("ids[9]: BREACH detected, unexpected change to /etc/passwd")
        elif kind == "panic":
            ticks[s]["lines"].append("kernel: EXT4-fs error (device sda1): bad block")
        else:
            at = T0 + timedelta(seconds=s * STEP - 120)
            hazards.append(Hazard(2, "usgs", "earthquake", "moderate", "M 5.6 near node", 13.2, 80.3, 150, True,
                                  at, at + timedelta(hours=6)))
            ticks[s + 10]["lines"].append("systemd[1]: Failed to start postgresql.service")
        injected.append(Injected(kind, s, s + 900 // STEP, True))

    # Subtle real incidents that fall under every threshold, so a miss is expected.
    for _ in range(1):
        s = place(600)
        for k in range(5):
            ticks[s + k * 20]["lines"].append("sshd[7]: Failed password for admin from 203.0.113.50 port 22 ssh2")
        injected.append(Injected("subtle_slow_login_attack", s, s + 720 // STEP, True))
    return ticks, injected, hazards


def run_one(seed: int, pol) -> dict:
    rng = random.Random(seed)
    ticks, injected, hazards = scenario(rng)
    det = ZScoreDetector(pol.detection)
    matcher = SignatureMatcher(pol.signatures, pol.self_log_tags)
    signals: list[Signal] = []
    base_alerts: list[tuple[int, str]] = []
    prop_alerts: list[tuple[int, str]] = []
    last_base: dict[str, int] = {}
    open_until: dict[str, int] = {}

    for i, t in enumerate(ticks):
        now = T0 + timedelta(seconds=i * STEP)
        fresh: list[Signal] = []
        for name in ("cpu", "mem", "disk"):
            a = det.observe("sim", name, now, t[name])
            if a:
                fresh.append(Signal(now, "metric", name, "weak", {
                    "value": a.value, "reason": a.reason, "duration_s": a.duration_s}))
        for line in t["lines"]:
            for m in matcher.match(line):
                fresh.append(Signal(now, "log", m.class_, m.strength, {**m.attrs, "signature": m.name}))
        for s in fresh:
            key = s.name
            if i - last_base.get(key, -10**9) > 600 // STEP:
                base_alerts.append((i, key))
            last_base[key] = i
        signals.extend(fresh)
        horizon = now - timedelta(seconds=pol.correlation.window_s)
        signals = [s for s in signals if s.ts >= horizon]
        if signals or any(h.starts_at <= now <= h.expires_at for h in hazards):
            for d in evaluate(NODE, signals, hazards, now, pol.correlation):
                if d.severity != "HIGH":
                    continue
                if i > open_until.get(d.category, -1):
                    prop_alerts.append((i, d.category))
                open_until[d.category] = i + pol.correlation.auto_resolve_s // STEP

    return {"base": score(base_alerts, injected), "prop": score(prop_alerts, injected)}


def score(alerts: list[tuple[int, str]], injected: list[Injected]) -> dict:
    real = [x for x in injected if x.real]
    margin = 120 // STEP
    tp = fp = 0
    for at, _ in alerts:
        if any(x.start - margin <= at <= x.end + margin for x in real):
            tp += 1
        else:
            fp += 1
    found, delays, by_kind = 0, [], {}
    for x in real:
        hits = [at for at, _ in alerts if x.start - margin <= at <= x.end + margin]
        by_kind.setdefault(x.kind, [0, 0])
        by_kind[x.kind][1] += 1
        if hits:
            found += 1
            by_kind[x.kind][0] += 1
            delays.append(max(0, min(hits) - x.start) * STEP)
    return {"alerts": len(alerts), "tp": tp, "fp": fp, "found": found, "real": len(real),
            "delays": delays, "by_kind": by_kind}


def summarise(rows: list[dict], key: str) -> dict:
    tp = sum(r[key]["tp"] for r in rows)
    fp = sum(r[key]["fp"] for r in rows)
    found = sum(r[key]["found"] for r in rows)
    real = sum(r[key]["real"] for r in rows)
    delays = [d for r in rows for d in r[key]["delays"]]
    days = len(rows) * HOURS / 24
    by_kind: dict[str, list[int]] = {}
    for r in rows:
        for kind, (hit, total) in r[key]["by_kind"].items():
            by_kind.setdefault(kind, [0, 0])
            by_kind[kind][0] += hit
            by_kind[kind][1] += total
    return {
        "alerts": tp + fp, "false_alerts": fp, "false_alerts_per_day": round(fp / days, 1),
        "alert_precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "incidents_found": found, "incidents_total": real, "incident_recall": round(found / real, 3),
        "median_detection_delay_s": statistics.median(delays) if delays else None,
        "found_by_kind": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_kind.items())},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--out", type=Path, default=ROOT / "reports" / "correlation_eval.json")
    args = ap.parse_args()
    pol = load_policy(ROOT / "config" / "config.json")
    rows = [run_one(seed, pol) for seed in range(args.seeds)]
    report = {
        "warning": "Simulated data, written by the rule author. Checks logic, not field performance.",
        "simulated_runs": args.seeds, "hours_per_run": HOURS,
        "baseline_siloed": summarise(rows, "base"),
        "proposed_correlation": summarise(rows, "prop"),
    }
    args.out.parent.mkdir(exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
