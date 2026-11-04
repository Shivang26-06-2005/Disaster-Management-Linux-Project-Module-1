#!/usr/bin/env python3
"""Module 1 demo: run the real monitoring and detection code. Needs no database or Docker.

    python scripts/module1_demo.py
    python scripts/module1_demo.py --report "Bridge collapsed and houses destroyed by the flood"

The computer's readings are live. The log lines and disasters are samples, and nothing
on this computer is changed.
"""
from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import psutil  # noqa: E402

from sentinel.config import load_policy  # noqa: E402
from sentinel.correlation.engine import Hazard, Node, Signal, evaluate  # noqa: E402
from sentinel.detection.signatures import SignatureMatcher  # noqa: E402
from sentinel.detection.zscore import ZScoreDetector  # noqa: E402

NOW = datetime.now(timezone.utc)
NODE = Node("demo-node", 13.08, 80.27)
DEFAULT_REPORTS = [
    "Bridge collapsed and many houses destroyed by the flood, roads are gone",
    "Light rain in the area today, everything is open and no damage so far",
]


def hazard(verified: bool, title: str) -> Hazard:
    return Hazard(
        id=1, source="drill" if verified else "citizen", hazard_type="earthquake", severity="moderate",
        title=title, lat=13.2, lon=80.5, radius_km=150.0, verified=verified,
        starts_at=NOW - timedelta(minutes=5), expires_at=NOW + timedelta(hours=1),
    )


SCENARIOS = [
    ("Normal activity", ["sshd[77]: Accepted publickey for admin from 10.0.0.5 port 50022",
                         "app[12]: scan finished, no critical findings"], []),
    ("One stray failure", ["cron[12]: nightly report job FAILED"], []),
    ("Security breach", ["ids[901]: BREACH detected, unexpected change to /etc/passwd"], []),
    ("Repeated failed logins", [f"sshd[77]: Failed password for root from 203.0.113.9 port {40000 + i} ssh2"
                                for i in range(12)], []),
    ("Service keeps failing", ["systemd[1]: nginx.service: Failed with result 'exit-code'."] * 3, []),
    ("Earthquake alert plus a stray failure", ["cron[12]: nightly report job FAILED"],
     [hazard(True, "DEMO earthquake alert")]),
    ("Unverified public report plus a stray failure", ["cron[12]: nightly report job FAILED"],
     [hazard(False, "Someone posted about an earthquake")]),
]


def show_live_readings() -> None:
    print("Live readings from this computer")
    print(f"  CPU {psutil.cpu_percent(interval=1):.0f}%   Memory {psutil.virtual_memory().percent:.0f}%   "
          f"Disk {psutil.disk_usage('/').percent:.0f}%\n")


def show_anomaly_detection(policy) -> None:
    print("Anomaly detection on a sample CPU spike")
    detector = ZScoreDetector(policy.detection)
    rng = random.Random(7)
    t0 = NOW - timedelta(minutes=30)
    for i in range(120):
        detector.observe("demo-node", "cpu", t0 + timedelta(seconds=5 * i), rng.gauss(25, 3))
    print("  120 normal samples around 25%: no alert")
    for i in range(120, 126):
        value = rng.gauss(90, 1)
        found = detector.observe("demo-node", "cpu", t0 + timedelta(seconds=5 * i), value)
        if found:
            print(f"  Alert at {found.value:.0f}%: z-score {found.z}, usual level {found.mean:.0f}%, "
                  f"after {i - 119} high samples\n")
            return
    print("  No alert\n")


def show_correlation(policy) -> None:
    print("Log detection and correlation on sample incidents")
    matcher = SignatureMatcher(policy.signatures, policy.self_log_tags)
    for name, lines, hazards in SCENARIOS:
        signals = [
            Signal(NOW - timedelta(seconds=len(lines) - i), "log", m.class_, m.strength, {**m.attrs, "signature": m.name})
            for i, line in enumerate(lines) for m in matcher.match(line)
        ]
        decisions = evaluate(NODE, signals, hazards, NOW, policy.correlation)
        print(f"  {name}")
        if not decisions:
            print("    Nothing to report")
        for d in decisions:
            acted = "acts on it" if d.severity == "HIGH" else "records it, takes no action"
            print(f"    {d.severity}: {d.title} ({acted})")
            print(f"    Why: {d.reasons[0]}")
    print()


def show_severity_model(reports: list[str]) -> None:
    from sentinel.ml.infer import SeverityModel

    print("AI damage rating of written disaster reports (macro-F1 on its test set: 0.45 for text alone)")
    model = SeverityModel(ROOT / "models")
    for text in reports:
        result = model.predict(text, None)
        print(f'  "{text}"')
        print(f"    {result['severity_label']} damage, {result['reliability']:.0%} reliability")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", help="Rate your own written disaster report instead of the samples")
    args = parser.parse_args()
    policy = load_policy(ROOT / "config" / "config.json")
    show_live_readings()
    show_anomaly_detection(policy)
    show_correlation(policy)
    show_severity_model([args.report] if args.report else DEFAULT_REPORTS)


if __name__ == "__main__":
    main()
