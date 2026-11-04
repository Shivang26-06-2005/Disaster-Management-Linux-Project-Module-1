from datetime import datetime, timedelta, timezone

from sentinel.detection.signatures import SignatureMatcher
from sentinel.detection.zscore import ZScoreDetector

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def feed(det, values, start=0, step=5):
    out = []
    for i, v in enumerate(values):
        found = det.observe("n", "cpu", T0 + timedelta(seconds=(start + i) * step), v)
        if found:
            out.append(found)
    return out


def noisy(base, n):
    return [base + ((i * 7) % 5) - 2 for i in range(n)]


def test_no_alert_during_warm_up_or_on_stable_load(pol):
    det = ZScoreDetector(pol.detection)
    assert feed(det, noisy(30, 300)) == []


def test_sustained_spike_fires_only_after_consecutive_samples(pol):
    det = ZScoreDetector(pol.detection)
    feed(det, noisy(30, 100))
    assert feed(det, [90, 90], start=100) == []
    found = feed(det, [90], start=102)
    assert len(found) == 1 and found[0].reason == "z_score" and found[0].z > 3


def test_one_sample_spike_is_ignored(pol):
    det = ZScoreDetector(pol.detection)
    feed(det, noisy(30, 100))
    # 99 is over the ceiling, but a single sample cannot complete the streak.
    assert feed(det, [99, 30, 30, 30], start=100) == []


def test_flat_idle_cpu_does_not_alert_on_harmless_rise(pol):
    det = ZScoreDetector(pol.detection)
    feed(det, [1.0] * 100)
    # An enormous z-score without min_std, but 12% CPU is not a problem.
    assert feed(det, [12.0] * 20, start=100) == []


def test_anomaly_does_not_poison_the_baseline(pol):
    det = ZScoreDetector(pol.detection)
    feed(det, noisy(30, 100))
    fired = feed(det, [90] * 30, start=100)
    assert fired
    state = det._states[("n", "cpu")]
    assert state.stats()[0] < 35


def test_slow_leak_hits_the_ceiling_even_with_low_z(pol):
    det = ZScoreDetector(pol.detection)
    ramp = [60 + i * 0.1 for i in range(400)]
    found = [
        a for i, v in enumerate(ramp)
        if (a := det.observe("n", "mem", T0 + timedelta(seconds=i * 5), v))
    ]
    assert found and found[0].reason == "ceiling" and found[0].value >= 95


def test_lasting_shift_becomes_the_new_normal(pol):
    det = ZScoreDetector(pol.detection)
    feed(det, noisy(30, 100))
    feed(det, [85] * (pol.detection.adapt_after + 1), start=100)
    assert det._states[("n", "cpu")].stats()[0] > 50


def test_gap_in_telemetry_resets_the_streak(pol):
    det = ZScoreDetector(pol.detection)
    feed(det, noisy(30, 100))
    feed(det, [90, 90], start=100)
    assert feed(det, [90], start=100 + 100) == []


def test_baselines_are_per_node(pol):
    det = ZScoreDetector(pol.detection)
    for i in range(100):
        det.observe("busy", "cpu", T0 + timedelta(seconds=i * 5), 75 + (i % 3))
        det.observe("idle", "cpu", T0 + timedelta(seconds=i * 5), 20 + (i % 3))
    results = {}
    for node in ("busy", "idle"):
        for i in range(5):
            found = det.observe(node, "cpu", T0 + timedelta(seconds=(100 + i) * 5), 78)
            results[node] = results.get(node) or found
    assert results["busy"] is None and results["idle"] is not None


def matcher(pol):
    return SignatureMatcher(pol.signatures, pol.self_log_tags)


def classes(pol, line):
    return [m.class_ for m in matcher(pol).match(line)]


def test_slide_keywords_match(pol):
    assert classes(pol, "app[1]: CRITICAL database unavailable") == ["critical"]
    assert classes(pol, "ids[2]: BREACH detected on /etc/passwd") == ["breach"]
    assert classes(pol, "cron[3]: backup job FAILED") == ["failed"]


def test_deck_status_line_does_not_trigger(pol):
    assert classes(pol, "Log Ingestion -> Scanned /var/log/syslog. No critical anomalies.") == []
    assert classes(pol, "scan finished, no CRITICAL findings") == []
    assert classes(pol, "0 FAILED, 12 passed") == []


def test_keyword_inside_other_words_does_not_match(pol):
    assert classes(pol, "noncritical maintenance finished") == []
    assert classes(pol, "the breach-of-contract document was archived") == []


def test_own_log_lines_are_ignored_to_prevent_feedback(pol):
    assert classes(pol, "host sentinel-recovery[9]: BREACH evidence preserved") == []
    assert classes(pol, "host sentinel-agent: CRITICAL something") == []


def test_ssh_failure_extracts_valid_ip_and_user(pol):
    match = matcher(pol).match("sshd[7]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2")[0]
    assert match.class_ == "auth_failed"
    assert match.attrs == {"ip": "203.0.113.9", "user": "admin"}


def test_malformed_ip_in_log_is_not_extracted(pol):
    match = matcher(pol).match("sshd[7]: Failed password for root from 999.1.1.1; rm -rf / port 22")[0]
    assert "ip" not in match.attrs


def test_service_name_extraction(pol):
    match = matcher(pol).match("systemd[1]: nginx.service: Failed with result 'exit-code'.")[0]
    assert match.class_ == "failed" and match.attrs["service"] == "nginx"


def test_shell_metacharacters_never_reach_service_name(pol):
    match = matcher(pol).match("systemd[1]: Failed to start evil;reboot.service")[0]
    assert ";" not in match.attrs.get("service", "")


def test_very_long_line_is_capped(pol):
    assert classes(pol, "x" * 50000 + " CRITICAL") == []
