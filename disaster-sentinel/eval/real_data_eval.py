"""Check the detectors against public labelled and real data, not just simulation.

    python eval/real_data_eval.py

1. NAB realAWSCloudwatch EC2 CPU series with human-labelled anomaly windows.
2. LogHub Linux_2k.log, real syslog lines with no labels, to see what the signatures do.

Both are downloaded at run time from GitHub and are not redistributed in this project.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sentinel.config import Detection, MetricRule, load_policy
from sentinel.detection.signatures import SignatureMatcher
from sentinel.detection.zscore import ZScoreDetector

ROOT = Path(__file__).resolve().parents[1]
NAB = "https://raw.githubusercontent.com/numenta/NAB/master"
LOGHUB = "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log"


def get(url: str, cache: Path) -> bytes:
    path = cache / re.sub(r"[^A-Za-z0-9._-]", "_", url.split("/master/")[-1])
    if not path.exists():
        cache.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=60) as r:
            path.write_bytes(r.read())
    return path.read_bytes()


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.split(".")[0]).replace(tzinfo=timezone.utc)


def nab_config(floor: float, ceiling: float = 1000.0) -> Detection:
    # NAB samples every 5 minutes, so windows are scaled to about 1 day of baseline.
    return Detection(window=288, min_samples=72, z_threshold=3.0, min_std=2.0, consecutive=2,
                     adapt_after=72, refire_every=12, max_gap_s=1800,
                     metrics={"cpu": MetricRule(floor=floor, ceiling=ceiling)})


def score_series(rows, windows, alert_at) -> dict:
    hits = [False] * len(windows)
    outside = 0
    for ts in alert_at:
        inside = False
        for i, (a, b) in enumerate(windows):
            if a <= ts <= b:
                hits[i] = True
                inside = True
        outside += not inside
    return {"windows_found": sum(hits), "windows": len(windows), "alerts_outside": outside,
            "alerts_inside": len(alert_at) - outside}


def run_nab(cache: Path) -> dict:
    labels = json.loads(get(f"{NAB}/labels/combined_windows.json", cache))
    series = [k for k in labels if k.startswith("realAWSCloudwatch/ec2_cpu_utilization")]
    methods = {
        "fixed_threshold_90": None,
        "zscore_no_floor": nab_config(floor=0.0),
        "zscore_with_deck_floor_70": nab_config(floor=70.0),
    }
    totals = {m: Counter() for m in methods}
    samples = 0
    for name in series:
        text = get(f"{NAB}/data/{name}", cache).decode()
        rows = [(parse_ts(r["timestamp"]), float(r["value"])) for r in csv.DictReader(text.splitlines())]
        samples += len(rows)
        windows = [(parse_ts(a), parse_ts(b)) for a, b in labels[name]]
        for method, cfg in methods.items():
            if cfg is None:
                alerts = [ts for ts, v in rows if v >= 90]
            else:
                det = ZScoreDetector(cfg)
                alerts = [ts for ts, v in rows if det.observe("n", "cpu", ts, v)]
            totals[method].update(score_series(rows, windows, alerts))
    out = {"series": len(series), "samples": samples}
    for method, t in totals.items():
        all_alerts = t["alerts_inside"] + t["alerts_outside"]
        out[method] = {
            "windows_found": f"{t['windows_found']}/{t['windows']}",
            "alerts_inside_windows": t["alerts_inside"], "alerts_outside_windows": t["alerts_outside"],
            "alert_precision": round(t["alerts_inside"] / all_alerts, 3) if all_alerts else None,
        }
    return out


def run_loghub(cache: Path, pol) -> dict:
    lines = get(LOGHUB, cache).decode(errors="replace").splitlines()
    matcher = SignatureMatcher(pol.signatures, pol.self_log_tags)
    classes, names, ips = Counter(), Counter(), Counter()
    examples = {}
    for line in lines:
        for m in matcher.match(line):
            classes[m.class_] += 1
            names[m.name] += 1
            examples.setdefault(m.name, line[:150])
            if m.attrs.get("ip"):
                ips[m.attrs["ip"]] += 1
    return {
        "lines": len(lines), "matches_by_class": dict(classes), "matches_by_signature": dict(names),
        "top_ips": ips.most_common(5), "example_per_signature": examples,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", type=Path, default=ROOT / "data" / "eval_cache")
    ap.add_argument("--out", type=Path, default=ROOT / "reports" / "real_data_eval.json")
    args = ap.parse_args()
    pol = load_policy(ROOT / "config" / "config.json")
    report = {"nab_cpu": run_nab(args.cache), "loghub_linux_2k": run_loghub(args.cache, pol)}
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
