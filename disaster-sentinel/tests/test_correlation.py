from datetime import datetime, timedelta, timezone

from sentinel.correlation.engine import Hazard, Node, Signal, evaluate, haversine_km

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
CHENNAI = Node("chennai", 13.08, 80.27)


def metric(age=30, value=92.0, duration=20, reason="z_score", name="cpu"):
    return Signal(NOW - timedelta(seconds=age), "metric", name, "weak",
                  {"value": value, "duration_s": duration, "reason": reason})


def log(name, age=30, strength="weak", **attrs):
    return Signal(NOW - timedelta(seconds=age), "log", name, strength, attrs)


def hazard(lat=13.2, lon=80.3, verified=True, severity="moderate", radius=200.0, source="usgs"):
    return Hazard(1, source, "earthquake", severity, "M 5.5 near Chennai", lat, lon, radius, verified,
                  NOW - timedelta(hours=1), NOW + timedelta(hours=5))


def run(pol, signals=(), hazards=(), node=CHENNAI):
    return {d.category: d for d in evaluate(node, list(signals), list(hazards), NOW, pol.correlation)}


def test_haversine_chennai_to_delhi():
    assert 1700 < haversine_km(13.08, 80.27, 28.61, 77.21) < 1800


def test_isolated_metric_spike_stays_low_with_no_action(pol):
    d = run(pol, [metric()])
    assert list(d) == ["isolated_signal"] and d["isolated_signal"].severity == "LOW"


def test_single_failed_line_stays_low(pol):
    d = run(pol, [log("failed", service="nginx")])
    assert d["isolated_signal"].severity == "LOW"


def test_metric_and_log_together_raise_to_high(pol):
    d = run(pol, [metric(), log("failed", service="nginx")])
    assert d["service_failure"].severity == "HIGH"
    assert d["service_failure"].attrs["service"] == "nginx"
    assert "isolated_signal" not in d


def test_signals_too_far_apart_do_not_corroborate(pol):
    d = run(pol, [metric(age=500), log("failed", age=10, service="nginx")])
    assert "service_failure" not in d


def test_old_signals_fall_out_of_the_window(pol):
    assert run(pol, [metric(age=pol.correlation.window_s + 60)]) == {}


def test_sustained_metric_raises_without_a_second_modality(pol):
    d = run(pol, [metric(duration=pol.correlation.sustained_s)])
    assert d["resource_exhaustion"].severity == "HIGH"


def test_ceiling_breach_raises_immediately(pol):
    d = run(pol, [metric(value=99, reason="ceiling", name="disk")])
    assert d["resource_exhaustion"].severity == "HIGH"


def test_repeated_service_failure_raises(pol):
    d = run(pol, [log("failed", age=i * 10, service="nginx") for i in range(pol.correlation.service_failed_count)])
    assert d["service_failure"].severity == "HIGH"


def test_breach_is_high_with_no_other_evidence(pol):
    d = run(pol, [log("breach", strength="hard", signature="breach_keyword")])
    assert d["cyber_breach"].severity == "HIGH"


def test_hazard_never_suppresses_a_breach(pol):
    d = run(pol, [log("breach", strength="hard", signature="breach_keyword"), metric()], [hazard()])
    assert d["cyber_breach"].severity == "HIGH"
    assert d["hazard_infrastructure"].severity == "HIGH"


def test_brute_force_needs_the_threshold_from_one_address(pol):
    n = pol.correlation.brute_force_count
    spread = [log("auth_failed", age=i, ip=f"203.0.113.{i}") for i in range(n)]
    assert "brute_force" not in run(pol, spread)
    same = [log("auth_failed", age=i, ip="203.0.113.9") for i in range(n)]
    d = run(pol, same)
    assert d["brute_force"].attrs["ip"] == "203.0.113.9"
    assert "isolated_signal" not in d


def test_weak_signal_near_verified_hazard_is_high(pol):
    d = run(pol, [metric()], [hazard()])
    assert d["hazard_infrastructure"].severity == "HIGH"
    assert any("km away" in r for r in d["hazard_infrastructure"].reasons)


def test_same_signal_with_distant_hazard_stays_low(pol):
    d = run(pol, [metric()], [hazard(lat=28.6, lon=77.2)])
    assert list(d) == ["isolated_signal"]


def test_node_going_silent_near_hazard_is_high(pol):
    silent = Signal(NOW - timedelta(seconds=10), "heartbeat", "silent", "weak", {})
    assert run(pol, [silent], [hazard()])["hazard_infrastructure"].severity == "HIGH"
    assert run(pol, [silent])["isolated_signal"].severity == "LOW"


def test_unverified_report_never_raises_severity(pol):
    report = hazard(verified=False, severity="extreme", source="citizen")
    d = run(pol, [metric()], [report])
    assert list(d) == ["isolated_signal"] and d["isolated_signal"].severity == "LOW"
    assert any("Unverified" in r for r in d["isolated_signal"].reasons)
    assert run(pol, [], [report]) == {}


def test_expired_hazard_is_ignored(pol):
    old = Hazard(1, "usgs", "earthquake", "severe", "old", 13.1, 80.3, 200, True,
                 NOW - timedelta(days=3), NOW - timedelta(days=2))
    assert run(pol, [metric()], [old]).keys() == {"isolated_signal"}


def test_severe_hazard_alone_is_a_precaution_and_moderate_is_a_note(pol):
    assert run(pol, [], [hazard(severity="severe")])["hazard_watch"].severity == "HIGH"
    assert run(pol, [], [hazard(severity="moderate")])["hazard_watch"].severity == "LOW"


def test_node_without_coordinates_cannot_match_hazards(pol):
    d = run(pol, [metric()], [hazard()], node=Node("nowhere"))
    assert list(d) == ["isolated_signal"]
