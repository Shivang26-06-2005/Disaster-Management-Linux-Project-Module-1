"""End-to-end flows through the real database, API, workers, agent code and recovery.sh."""
import hashlib
import json
import os
import subprocess
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from sentinel import db
from sentinel.compliance import audit
from sentinel.compliance.report import build_report, render_text
from sentinel.services import dashboard, hazards, ingest
from sentinel.services.analytics import Analytics
from sentinel.services.recovery import RecoveryEngine

ROOT = Path(__file__).resolve().parents[1]
FIX = Path(__file__).parent / "fixtures"
SCRIPT = str(ROOT / "scripts" / "recovery.sh")
TOKEN = "node-token-for-tests"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def now():
    return datetime.now(timezone.utc)


@pytest.fixture()
def node(engine):
    with engine.begin() as conn:
        conn.execute(db.nodes.insert().values(
            id="chennai-1", token_hash=hashlib.sha256(TOKEN.encode()).hexdigest(),
            lat=13.08, lon=80.27, region="Chennai", last_seen=now(),
        ))
    return "chennai-1"


@pytest.fixture()
def client():
    return TestClient(ingest.app)


def send(client, lines=(), samples=(), batch_id=None, headers=HEADERS):
    return client.post("/v1/telemetry", headers=headers, json={
        "batch_id": batch_id or str(uuid.uuid4()), "sent_at": now().isoformat(),
        "status": {"hostname": "h1", "mode": "dry_run", "recovery_ready": True, "sources": ["/var/log/syslog"]},
        "metrics": list(samples),
        "logs": [{"ts": now().isoformat(), "source": "/var/log/syslog", "line": l} for l in lines],
    })


def incidents_of(engine):
    with engine.connect() as conn:
        return conn.execute(sa.select(db.incidents).order_by(db.incidents.c.id)).mappings().all()


def actions_of(engine):
    with engine.connect() as conn:
        return conn.execute(sa.select(db.recovery_actions).order_by(db.recovery_actions.c.id)).mappings().all()


def make_agent(tmp_path, **over):
    from sentinel.agent.daemon import Agent

    cfg = {
        "server": "http://testserver", "token": TOKEN, "spool_dir": str(tmp_path / "spool"),
        "recovery_script": SCRIPT, "log_files": [], "use_journal_if_no_files": False,
        "allowed_services": ["nginx"], "allow_isolate": True, **over,
    }
    return Agent(cfg)


# Ingestion -----------------------------------------------------------------------

def test_telemetry_requires_a_valid_token(node, client):
    assert send(client, headers={}).status_code == 401
    assert send(client, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert send(client).status_code == 200


def test_retried_batch_is_not_stored_twice(engine, node, client):
    batch = str(uuid.uuid4())
    assert send(client, ["hello"], batch_id=batch).json()["accepted"] is True
    assert send(client, ["hello"], batch_id=batch).json()["duplicate"] is True
    with engine.connect() as conn:
        assert conn.execute(sa.select(sa.func.count()).select_from(db.log_events)).scalar() == 1


def test_future_timestamp_is_clamped(engine, node, client):
    future = (now() + timedelta(days=30)).isoformat()
    assert send(client, samples=[{"ts": future, "cpu": 1.0}]).status_code == 200
    with engine.connect() as conn:
        ts = conn.execute(sa.select(db.metrics.c.ts)).scalar()
    assert ts < now() + timedelta(minutes=1)


def test_out_of_range_metric_is_rejected(node, client):
    assert send(client, samples=[{"ts": now().isoformat(), "cpu": 900}]).status_code == 422


def test_nul_bytes_in_logs_do_not_break_storage(node, client):
    assert send(client, ["bad\x00line"]).status_code == 200


# Detection through recovery ------------------------------------------------------

def test_breach_flows_to_evidence_action_report_and_audit(engine, node, client, pol, tmp_path):
    assert send(client, ["ids[9]: BREACH detected on web tier"]).status_code == 200
    worker = Analytics(engine, pol)
    worker.tick()
    inc = incidents_of(engine)
    assert [(i["category"], i["severity"]) for i in inc] == [("cyber_breach", "HIGH")]
    assert inc[0]["certin_type"] == "Compromise of critical systems/information"
    remaining = (inc[0]["certin_deadline"] - inc[0]["noticed_at"]).total_seconds()
    assert remaining == 6 * 3600

    RecoveryEngine(engine, pol).tick()
    acts = actions_of(engine)
    assert [a["action"] for a in acts] == ["preserve_evidence"]
    assert incidents_of(engine)[0]["escalated_at"] is not None

    claimed = client.post("/v1/actions/claim", headers=HEADERS).json()["actions"]
    assert client.post("/v1/actions/claim", headers=HEADERS).json()["actions"] == []
    agent = make_agent(tmp_path)
    outcome = agent.run_action(claimed[0])
    assert outcome["exit_code"] == 0 and outcome["dry_run"] is True
    assert client.post(f"/v1/actions/{claimed[0]['id']}/result", headers=HEADERS, json=outcome).json()["status"] == "done"

    with engine.connect() as conn:
        report = build_report(conn, inc[0]["id"])
        verdict = audit.verify(conn)
    assert report["status"].startswith("DRAFT") and report["report_to"] == "incident@cert-in.org.in"
    assert report["actions_taken"][0]["simulated"] is True
    assert any("BREACH" in l["line"] for l in report["log_extract"])
    assert "DRAFT" in render_text(report)
    assert verdict.ok and verdict.batches == 1


def test_isolated_weak_signal_opens_low_and_triggers_nothing(engine, node, client, pol):
    send(client, ["cron[3]: backup job FAILED"])
    Analytics(engine, pol).tick()
    RecoveryEngine(engine, pol).tick()
    assert [(i["category"], i["severity"]) for i in incidents_of(engine)] == [("isolated_signal", "LOW")]
    assert actions_of(engine) == []


def test_repeat_signals_update_one_incident(engine, node, client, pol):
    worker = Analytics(engine, pol)
    for _ in range(3):
        send(client, ["ids: BREACH again"])
        worker.tick()
    assert len(incidents_of(engine)) == 1


def test_low_incident_escalates_when_evidence_grows(engine, node, client, pol):
    worker = Analytics(engine, pol)
    with engine.begin() as conn:
        conn.execute(db.hazard_events.insert().values(
            source="usgs", external_id="q1", hazard_type="earthquake", severity="moderate", title="M 5 near Chennai",
            lat=13.1, lon=80.3, radius_km=150, verified=True, starts_at=now() - timedelta(hours=1),
            expires_at=now() + timedelta(hours=1),
        ))
    worker.tick()
    assert [(i["category"], i["severity"]) for i in incidents_of(engine)] == [("hazard_watch", "LOW")]
    send(client, ["systemd: nginx.service: Failed with result"])
    worker.tick()
    cats = {i["category"]: i["severity"] for i in incidents_of(engine)}
    assert cats["hazard_infrastructure"] == "HIGH"


def test_real_metric_stream_detects_after_baseline(engine, node, client, pol):
    start = now() - timedelta(minutes=30)
    samples = [{"ts": (start + timedelta(seconds=i * 5)).isoformat(), "cpu": 20 + i % 3, "mem": 40.0, "disk": 50.0} for i in range(120)]
    send(client, samples=samples)
    worker = Analytics(engine, pol)
    worker.tick()
    assert incidents_of(engine) == []
    spike = [{"ts": (now() - timedelta(seconds=30 - i * 5)).isoformat(), "cpu": 95.0, "mem": 40.0, "disk": 50.0} for i in range(5)]
    send(client, samples=spike)
    worker.tick()
    assert [i["category"] for i in incidents_of(engine)] == ["isolated_signal"]


def test_restart_keeps_the_baseline(engine, node, client, pol):
    start = now() - timedelta(minutes=30)
    send(client, samples=[{"ts": (start + timedelta(seconds=i * 5)).isoformat(), "cpu": 20.0, "mem": 40.0, "disk": 50.0} for i in range(120)])
    Analytics(engine, pol).tick()
    fresh = Analytics(engine, pol)
    send(client, samples=[{"ts": (now() - timedelta(seconds=30 - i * 5)).isoformat(), "cpu": 95.0, "mem": 40.0, "disk": 50.0} for i in range(5)])
    fresh.tick()
    with engine.connect() as conn:
        row = conn.execute(sa.select(db.detections).where(db.detections.c.modality == "metric")).mappings().first()
    assert row and row["attrs"]["reason"] == "z_score"


def test_silent_node_is_flagged(engine, node, pol):
    with engine.begin() as conn:
        conn.execute(db.nodes.update().values(last_seen=now() - timedelta(minutes=10)))
    Analytics(engine, pol).tick()
    assert incidents_of(engine)[0]["category"] == "isolated_signal"
    assert "stopped reporting" in incidents_of(engine)[0]["summary"]


def test_low_incident_auto_resolves_but_breach_waits_for_a_person(engine, node, client, pol):
    send(client, ["cron: job FAILED", "ids: BREACH"])
    worker = Analytics(engine, pol)
    worker.tick()
    later = now() + timedelta(seconds=pol.correlation.auto_resolve_s + 700)
    with engine.begin() as conn:
        conn.execute(db.nodes.update().values(last_seen=later))  # The node kept reporting.
    worker.tick(later)
    states = {i["category"]: i["status"] for i in incidents_of(engine)}
    assert states == {"isolated_signal": "resolved", "cyber_breach": "open"}


def test_action_cooldown_escalates_instead_of_looping(engine, node, client, pol):
    send(client, ["systemd: nginx.service: Failed"] * 3)
    worker, recovery = Analytics(engine, pol), RecoveryEngine(engine, pol)
    worker.tick()
    recovery.tick()
    assert [a["arg"] for a in actions_of(engine)] == ["nginx"]
    with engine.begin() as conn:
        conn.execute(db.incidents.update().values(status="resolved"))
    send(client, ["systemd: nginx.service: Failed"] * 3)
    worker.tick()
    recovery.tick()
    assert len(actions_of(engine)) == 1
    assert incidents_of(engine)[-1]["escalated_at"] is not None


def test_uncollected_action_expires_and_escalates(engine, node, client, pol):
    send(client, ["systemd: nginx.service: Failed"] * 3)
    Analytics(engine, pol).tick()
    recovery = RecoveryEngine(engine, pol)
    recovery.tick()
    recovery.tick(now() + timedelta(seconds=pol.recovery.action_ttl_s + 5))
    assert actions_of(engine)[0]["status"] == "expired"
    assert client.post("/v1/actions/claim", headers=HEADERS).json()["actions"] == []
    assert incidents_of(engine)[0]["escalated_at"] is not None


def test_node_cannot_touch_another_nodes_action(engine, node, client, pol):
    send(client, ["ids: BREACH"])
    Analytics(engine, pol).tick()
    RecoveryEngine(engine, pol).tick()
    other = "other-token"
    with engine.begin() as conn:
        conn.execute(db.nodes.insert().values(id="other", token_hash=hashlib.sha256(other.encode()).hexdigest()))
    headers = {"Authorization": f"Bearer {other}"}
    assert client.post("/v1/actions/claim", headers=headers).json()["actions"] == []
    action = actions_of(engine)[0]["id"]
    body = {"exit_code": 0, "dry_run": True, "output": ""}
    assert client.post(f"/v1/actions/{action}/result", headers=headers, json=body).status_code == 404


# Agent policy and recovery.sh ----------------------------------------------------

@pytest.mark.parametrize("action,arg,why", [
    ("rm_everything", None, "allowed_actions"),
    ("restart_service", "postgres", "allowed_services"),
    ("restart_service", "nginx; reboot", "Invalid service"),
    ("isolate_ip", "not-an-ip", "Invalid IP"),
    ("isolate_ip", "127.0.0.1", "protected"),
    ("isolate_ip", "192.168.1.10", "protected"),
    ("preserve_evidence", "/etc", "no target"),
])
def test_agent_refuses_what_its_own_policy_forbids(tmp_path, action, arg, why):
    outcome = make_agent(tmp_path).run_action({"action": action, "arg": arg})
    assert outcome["exit_code"] == 126 and why in outcome["output"]


def test_isolation_is_off_unless_the_node_enables_it(tmp_path):
    outcome = make_agent(tmp_path, allow_isolate=False).run_action({"action": "isolate_ip", "arg": "203.0.113.9"})
    assert outcome["exit_code"] == 126


def test_agent_default_mode_is_simulation(tmp_path):
    agent = make_agent(tmp_path)
    outcome = agent.run_action({"action": "isolate_ip", "arg": "203.0.113.9"})
    assert outcome["dry_run"] is True and "DRY RUN" in outcome["output"]


def rec(tmp_path, *args, **env):
    full = {"PATH": os.environ["PATH"], "SENTINEL_RECOVERY_TEST_ROOT": str(tmp_path), **env}
    return subprocess.run([SCRIPT, *args], capture_output=True, text=True, env=full)


@pytest.mark.parametrize("args", [
    ("--enforce", "restart_service", "x;reboot"),
    ("--enforce", "restart_service", "--force"),
    ("--enforce", "restart_service", "sshd"),
    ("--enforce", "restart_service", "sentinel-agent"),
    ("--enforce", "isolate_ip", "1.2.3.4; reboot"),
    ("--enforce", "preserve_evidence", "/etc/shadow"),
    ("--enforce", "unknown"),
    ("--enforce",),
])
def test_recovery_script_rejects_bad_input_at_the_privilege_boundary(tmp_path, args):
    assert rec(tmp_path, *args).returncode != 0


def test_recovery_script_defaults_to_dry_run(tmp_path):
    out = rec(tmp_path, "restart_service", "nginx")
    assert out.returncode == 0 and "DRY RUN" in out.stdout


def test_preserve_evidence_writes_checksummed_archive(tmp_path):
    log_file = tmp_path / "syslog"
    log_file.write_text("line\n")
    out = rec(tmp_path, "--enforce", "preserve_evidence", SENTINEL_TEST_LOG_PATHS=str(log_file))
    assert out.returncode == 0, out.stderr
    archives = list((tmp_path / "evidence").glob("*.tar.gz"))
    assert len(archives) == 1
    assert subprocess.run(["sha256sum", "-c", f"{archives[0]}.sha256"], capture_output=True).returncode == 0


def test_backup_without_configured_paths_fails_clearly(tmp_path):
    out = rec(tmp_path, "--enforce", "backup_snapshot")
    assert out.returncode == 78 and "BACKUP_PATHS" in out.stderr


def test_clear_cache_removes_contents_only_of_listed_directories(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "x").write_text("x")
    keep = tmp_path / "keep"
    keep.write_text("keep")
    assert rec(tmp_path, "--enforce", "clear_cache", SENTINEL_TEST_CACHE_DIRS=str(cache)).returncode == 0
    assert cache.exists() and not (cache / "x").exists() and keep.exists()


@pytest.mark.parametrize("path", ["/", "/etc", "/var/log/nginx", "/home"])
def test_clear_cache_refuses_system_paths(tmp_path, path):
    assert rec(tmp_path, "--enforce", "clear_cache", SENTINEL_TEST_CACHE_DIRS=path).returncode == 65


def test_spool_keeps_batches_while_offline_and_is_bounded(tmp_path):
    agent = make_agent(tmp_path, spool_max_batches=3, server="http://127.0.0.1:9")
    for _ in range(5):
        agent.metrics.append({"ts": now().isoformat(), "cpu": 1.0})
        agent.flush_to_spool()
    assert len(agent.spool.files()) == 3 and agent.spool.dropped == 2
    assert agent.send_spool() is False
    assert len(agent.spool.files()) == 3


def test_tailer_follows_rotation(tmp_path):
    from sentinel.agent.daemon import Tailer

    path = tmp_path / "log"
    path.write_text("before\n")
    tail = Tailer(str(path))
    assert tail.read_lines() == []
    with path.open("a") as fh:
        fh.write("one\n")
    assert tail.read_lines() == ["one"]
    path.rename(tmp_path / "log.1")
    path.write_text("two\n")
    assert tail.read_lines() == []
    assert tail.read_lines() == ["two"]


# Tamper evidence -----------------------------------------------------------------

def add_entries(engine, n):
    with engine.begin() as conn:
        for i in range(n):
            audit.append(conn, "test", {"i": i})


def check(engine, anchor=None):
    with engine.connect() as conn:
        return audit.verify(conn, anchor)


def test_chain_verifies(engine):
    add_entries(engine, 20)
    assert check(engine).ok and check(engine).entries == 20


def test_database_blocks_changes_to_the_log(engine):
    add_entries(engine, 3)
    for statement in ("UPDATE audit_log SET kind='x' WHERE seq=1", "DELETE FROM audit_log WHERE seq=1", "TRUNCATE audit_log"):
        with pytest.raises(sa.exc.DBAPIError, match="append-only"):
            with engine.begin() as conn:
                conn.execute(sa.text(statement))


def disable_trigger(conn):
    conn.execute(sa.text("ALTER TABLE audit_log DISABLE TRIGGER USER"))


def test_edit_by_a_database_superuser_is_detected(engine):
    add_entries(engine, 5)
    with engine.begin() as conn:
        disable_trigger(conn)
        conn.execute(sa.text("UPDATE audit_log SET payload=:p WHERE seq=3"), {"p": '{"i":99}'})
    result = check(engine)
    assert not result.ok and any("Entry 3" in p for p in result.problems)


def test_deleted_middle_entry_is_detected(engine):
    add_entries(engine, 5)
    with engine.begin() as conn:
        disable_trigger(conn)
        conn.execute(sa.text("DELETE FROM audit_log WHERE seq=3"))
    assert not check(engine).ok


def test_forged_entry_without_the_key_is_detected(engine, monkeypatch):
    add_entries(engine, 2)
    monkeypatch.setenv("AUDIT_HMAC_KEY", "attacker-attacker-attacker-attacker-key")
    add_entries(engine, 1)
    monkeypatch.undo()
    assert not check(engine).ok


def test_cutting_off_the_tail_is_caught_by_the_anchor(engine, tmp_path):
    add_entries(engine, 5)
    anchor = str(tmp_path / "anchor.jsonl")
    with engine.connect() as conn:
        audit.write_anchor(conn, anchor)
    with engine.begin() as conn:
        disable_trigger(conn)
        conn.execute(sa.text("DELETE FROM audit_log WHERE seq>=4"))
        row = conn.execute(sa.text("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")).one()
        conn.execute(sa.text("UPDATE audit_head SET seq=:s, hash=:h"), {"s": row.seq, "h": row.hash})
    assert check(engine).ok, "Without an anchor the chain alone cannot see this"
    assert not check(engine, anchor).ok


def test_changed_stored_log_line_is_detected(engine, node, client):
    send(client, ["original line"])
    assert check(engine).ok
    with engine.begin() as conn:
        conn.execute(sa.text("UPDATE log_events SET line='nothing happened'"))
    result = check(engine)
    assert not result.ok and any("log batch" in p for p in result.problems)


def test_rolled_back_transaction_leaves_no_entry(engine):
    with pytest.raises(RuntimeError):
        with engine.begin() as conn:
            audit.append(conn, "test", {})
            raise RuntimeError("boom")
    assert check(engine).entries == 0


def test_concurrent_writers_never_fork_the_chain(engine):
    errors = []

    def write():
        try:
            for i in range(25):
                with engine.begin() as conn:
                    audit.append(conn, "test", {"i": i})
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=write) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    result = check(engine)
    assert result.ok and result.entries == 100


def test_retention_keeps_recent_rows_and_purges_old_ones(engine, node, client, pol):
    send(client, ["recent"])
    old = now() - timedelta(days=pol.compliance.retention_days + 2)
    with engine.begin() as conn:
        conn.execute(db.log_events.insert().values(ts=old, node_id="chennai-1", batch_id="x", seq=0, source="s", line="old"))
    Analytics(engine, pol).housekeeping()
    with engine.connect() as conn:
        lines = conn.execute(sa.select(db.log_events.c.line)).scalars().all()
    assert lines == ["recent"]


def test_policy_refuses_retention_under_180_days(tmp_path):
    from sentinel.config import load_policy

    data = json.loads((ROOT / "config" / "config.json").read_text())
    data["compliance"]["retention_days"] = 30
    path = tmp_path / "c.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="180"):
        load_policy(path)


# Least privilege -----------------------------------------------------------------

def test_component_roles_only_reach_their_own_tables(engine):
    url = engine.url
    passwords = {role: "test-password-1" for role in db.ROLE_GRANTS}
    db.migrate(engine, passwords)
    add_entries(engine, 1)

    def role_engine(role):
        return sa.create_engine(url.set(username=role, password="test-password-1"))

    forbidden = [
        ("sentinel_ingest", "SELECT * FROM incidents"),
        ("sentinel_ingest", "SELECT * FROM log_events"),
        ("sentinel_hazards", "SELECT * FROM nodes"),
        ("sentinel_analytics", "INSERT INTO recovery_actions (incident_id,node_id,action,status,expires_at) VALUES (1,'a','b','c',now())"),
        ("sentinel_recovery", "SELECT * FROM log_events"),
        ("sentinel_dashboard", "DELETE FROM log_events"),
        ("sentinel_dashboard", "UPDATE nodes SET token_hash='x'"),
        ("sentinel_ingest", "DELETE FROM audit_log"),
        ("sentinel_analytics", "UPDATE audit_log SET kind='x'"),
    ]
    for role, statement in forbidden:
        with pytest.raises(sa.exc.ProgrammingError, match="permission denied"):
            with role_engine(role).begin() as conn:
                conn.execute(sa.text(statement))
    with role_engine("sentinel_hazards").begin() as conn:
        audit.append(conn, "test", {"role": "hazards"})
    assert check(engine).ok


# Hazard poller -------------------------------------------------------------------

def test_hazard_poll_stores_once_and_one_feed_failing_does_not_stop_the_other(engine, pol):
    def get(url):
        if url == pol.hazards.usgs_url:
            return (FIX / "usgs.geojson").read_bytes()
        raise OSError("SACHET is down")

    status = hazards.poll_once(engine, pol, set(), get)
    assert status["usgs"]["ok"] and status["usgs"]["new"] == 2 and not status["sachet"]["ok"]
    assert hazards.poll_once(engine, pol, set(), get)["usgs"]["new"] == 0


def test_sachet_poll_fetches_each_alert_once(engine, pol):
    calls = []

    def get(url):
        calls.append(url)
        if url == pol.hazards.usgs_url:
            return b'{"features":[]}'
        if url == pol.hazards.sachet_url:
            return (FIX / "sachet_rss.xml").read_bytes()
        return (FIX / "sachet_cap.xml").read_bytes()

    known = set()
    assert hazards.poll_once(engine, pol, known, get)["sachet"]["new"] == 1
    hazards.poll_once(engine, pol, known, get)
    assert sum("FetchXMLFile" in c for c in calls) == 1


# Dashboard -----------------------------------------------------------------------

@pytest.fixture()
def web(engine, monkeypatch, tmp_path):
    monkeypatch.setenv("REPORT_IMAGE_DIR", str(tmp_path / "images"))
    dashboard._failures.clear()
    c = TestClient(dashboard.app)
    return c


def sign_in(web):
    assert web.post("/api/login", json={"password": os.environ["OPERATOR_PASSWORD"]}).status_code == 200
    web.headers["X-Requested-With"] = "sentinel"


def test_dashboard_requires_login(web):
    assert web.get("/api/overview").status_code == 401
    assert web.get("/api/reports").status_code == 401
    assert web.get("/").status_code == 200
    assert "default-src 'none'" in web.get("/").headers["content-security-policy"]


def test_login_lockout_after_repeated_failures(web):
    for _ in range(5):
        assert web.post("/api/login", json={"password": "nope"}).status_code == 401
    assert web.post("/api/login", json={"password": os.environ["OPERATOR_PASSWORD"]}).status_code == 429


def test_forged_or_expired_session_is_refused(web):
    assert web.get("/api/overview", cookies={"sentinel_session": "abc.def"}).status_code == 401
    expired = dashboard.make_session("operator", now=0)
    web.cookies.set("sentinel_session", expired)
    assert web.get("/api/overview").status_code == 401


def test_changes_need_the_csrf_header(web, engine, node, client, pol):
    assert web.post("/api/login", json={"password": os.environ["OPERATOR_PASSWORD"]}).status_code == 200
    send(client, ["ids: BREACH"])
    Analytics(engine, pol).tick()
    assert web.post("/api/incidents/1/resolve").status_code == 403
    web.headers["X-Requested-With"] = "sentinel"
    assert web.post("/api/incidents/1/resolve").status_code == 200


def test_overview_threat_levels_and_plain_language(web, engine, node, client, pol):
    sign_in(web)
    assert web.get("/api/overview").json()["threat"]["label"] == "LOW / STABLE"
    send(client, ["ids: BREACH detected"], samples=[{"ts": now().isoformat(), "cpu": 14.2, "mem": 42.8, "disk": 50}])
    Analytics(engine, pol).tick()
    RecoveryEngine(engine, pol).tick()
    data = web.get("/api/overview").json()
    assert data["threat"]["label"] == "HIGH / ACTION UNDERWAY" and data["monitoring_active"]
    assert data["nodes"][0]["cpu"] == 14.2
    assert data["incidents"][0]["certin"]["seconds_left"] > 5 * 3600
    text = json.dumps(data)
    assert "z_threshold" not in text and "pattern" not in text
    assert any("Telemetry Check" in line["text"] for line in data["feed"])
    assert any("Recovery Script Ready" in line["text"] for line in data["feed"])


def test_report_download_and_filing_mark(web, engine, node, client, pol):
    sign_in(web)
    send(client, ["ids: BREACH"])
    Analytics(engine, pol).tick()
    response = web.get("/api/incidents/1/report?format=txt")
    assert response.status_code == 200 and "DRAFT" in response.text and "attachment" in response.headers["content-disposition"]
    assert web.post("/api/incidents/1/filed", json={"reference": "CERT-123"}).status_code == 200
    report = web.get("/api/incidents/1/report").json()
    assert report["reference"] == "CERT-123" and report["reported_at"]


def test_action_approval_flow(web, engine, node, client, pol):
    sign_in(web)
    send(client, ["ids: BREACH"])
    Analytics(engine, pol).tick()
    with engine.begin() as conn:
        conn.execute(db.recovery_actions.insert().values(
            incident_id=1, node_id="chennai-1", action="clear_cache", status="awaiting_approval",
            expires_at=now() + timedelta(minutes=5),
        ))
    assert client.post("/v1/actions/claim", headers=HEADERS).json()["actions"] == []
    assert web.post("/api/actions/1/approve").json()["status"] == "pending"
    assert web.post("/api/actions/1/approve").status_code == 409
    assert len(client.post("/v1/actions/claim", headers=HEADERS).json()["actions"]) == 1


class FakeReply:
    status_code = 200
    headers = {"content-type": "application/json"}

    def __init__(self, severity="severe_damage"):
        self.severity = severity

    def json(self):
        return {"severity": self.severity, "severity_label": "Severe", "reliability": 0.7,
                "probabilities": {}, "mode": "text_only", "model_version": "test"}


def test_report_is_corroborated_by_official_alert_and_stays_unverified_otherwise(web, engine, monkeypatch):
    sign_in(web)
    monkeypatch.setattr(dashboard.httpx, "post", lambda *a, **k: FakeReply())
    first = web.post("/api/reports", data={"text": "Flood in Chennai, houses damaged"}).json()
    assert first["verification"] == "unverified" and first["location"] == "Chennai" and first["hazard_type"] == "flood"
    assert "Verify it" in first["advice"]["caution"]
    with engine.connect() as conn:
        added = conn.execute(sa.select(db.hazard_events)).mappings().all()
    assert len(added) == 1 and added[0]["verified"] is False

    assert web.post("/api/reports", data={"text": "Flood in  CHENNAI, houses damaged"}).json()["verification"] == "duplicate"

    with engine.begin() as conn:
        conn.execute(db.hazard_events.insert().values(
            source="sachet", external_id="a1", hazard_type="storm", severity="severe", title="Heavy rain, Chennai",
            lat=13.1, lon=80.3, radius_km=100, verified=True, starts_at=now() - timedelta(hours=1),
            expires_at=now() + timedelta(hours=1),
        ))
    third = web.post("/api/reports", data={"text": "River flood near Chennai airport today"}).json()
    assert third["verification"] == "corroborated" and third["official_match"]["source"] == "sachet"


def test_unrelated_official_alert_does_not_corroborate(web, engine, monkeypatch):
    sign_in(web)
    monkeypatch.setattr(dashboard.httpx, "post", lambda *a, **k: FakeReply())
    with engine.begin() as conn:
        conn.execute(db.hazard_events.insert().values(
            source="usgs", external_id="q", hazard_type="earthquake", severity="severe", title="Quake", lat=13.1, lon=80.3,
            radius_km=100, verified=True, starts_at=now() - timedelta(hours=1), expires_at=now() + timedelta(hours=1),
        ))
    assert web.post("/api/reports", data={"text": "Flood in Chennai"}).json()["verification"] == "unverified"


def test_photo_gps_data_is_removed_before_storage(web, engine, monkeypatch, tmp_path):
    import io

    from PIL import Image

    sign_in(web)
    monkeypatch.setattr(dashboard.httpx, "post", lambda *a, **k: FakeReply())
    exif = Image.Exif()
    exif[0x010F] = "SecretCameraMaker"
    buffer = io.BytesIO()
    Image.new("RGB", (50, 50), "red").save(buffer, "JPEG", exif=exif)
    assert b"SecretCameraMaker" in buffer.getvalue()
    result = web.post("/api/reports", files={"image": ("a.jpg", buffer.getvalue(), "image/jpeg")}).json()
    stored = web.get(f"/api/reports/{result['id']}/image")
    assert stored.status_code == 200 and b"SecretCameraMaker" not in stored.content


def test_empty_report_is_refused_with_direction(web):
    sign_in(web)
    response = web.post("/api/reports", data={"text": "  "})
    assert response.status_code == 422 and "description" in response.json()["detail"]


def test_verify_endpoint_reports_tampering(web, engine, node, client):
    sign_in(web)
    send(client, ["line"])
    assert web.post("/api/compliance/verify").json()["ok"] is True
    with engine.begin() as conn:
        conn.execute(sa.text("UPDATE log_events SET line='x'"))
    assert web.post("/api/compliance/verify").json()["ok"] is False


# Everything above runs as the database owner. This repeats the main flow with each
# component on its own restricted role, because a missing grant only shows up here.

def test_whole_flow_works_under_least_privilege_roles(engine, node, monkeypatch, pol, tmp_path):
    from sentinel.services import analytics as analytics_mod

    db.migrate(engine, {role: "test-password-1" for role in db.ROLE_GRANTS})

    def as_role(role):
        return sa.create_engine(engine.url.set(username=role, password="test-password-1"))

    ingest_engine = as_role("sentinel_ingest")
    monkeypatch.setattr(ingest, "get_engine", lambda: ingest_engine)
    api = TestClient(ingest.app)
    start = now() - timedelta(minutes=2)
    samples = [{"ts": (start + timedelta(seconds=i)).isoformat(), "cpu": 20.0, "mem": 40.0, "disk": 50.0} for i in range(5)]
    assert send(api, ["ids: BREACH", "systemd: nginx.service: Failed"] * 2, samples).status_code == 200

    worker = Analytics(as_role("sentinel_analytics"), pol)
    assert worker.tick() > 0
    worker.housekeeping()
    analytics_mod.record_profile(as_role("sentinel_analytics"), pol)
    recovery = RecoveryEngine(as_role("sentinel_recovery"), pol)
    recovery.tick()
    recovery.send_notifications()

    claimed = api.post("/v1/actions/claim", headers=HEADERS).json()["actions"]
    assert claimed
    body = {"exit_code": 0, "dry_run": True, "output": "ok"}
    assert api.post(f"/v1/actions/{claimed[0]['id']}/result", headers=HEADERS, json=body).json()["accepted"]

    def fetch(url):
        if url == pol.hazards.usgs_url:
            return (FIX / "usgs.geojson").read_bytes()
        if url == pol.hazards.sachet_url:
            return (FIX / "sachet_rss.xml").read_bytes()
        return (FIX / "sachet_cap.xml").read_bytes()

    status = hazards.poll_once(as_role("sentinel_hazards"), pol, set(), fetch)
    assert status["usgs"]["ok"] and status["sachet"]["ok"]

    dash_engine = as_role("sentinel_dashboard")
    monkeypatch.setattr(dashboard, "get_engine", lambda: dash_engine)
    monkeypatch.setenv("REPORT_IMAGE_DIR", str(tmp_path / "images"))
    monkeypatch.setattr(dashboard.httpx, "post", lambda *a, **k: FakeReply())
    dashboard._failures.clear()
    web = TestClient(dashboard.app)
    sign_in(web)
    overview = web.get("/api/overview").json()
    assert overview["threat"]["level"] == "high"
    assert web.get("/api/compliance").status_code == 200
    assert web.post("/api/compliance/verify").json()["ok"] is True
    incident = overview["incidents"][0]["id"]
    assert web.get(f"/api/incidents/{incident}/report?format=txt").status_code == 200
    assert web.post(f"/api/incidents/{incident}/filed", json={"reference": "x"}).status_code == 200
    assert web.post("/api/reports", data={"text": "Flood in Chennai, houses destroyed"}).status_code == 200
    assert web.get("/api/reports").status_code == 200
    assert web.post(f"/api/incidents/{incident}/resolve").status_code == 200
    with engine.connect() as conn:
        assert audit.verify(conn).ok


# Notifications -------------------------------------------------------------------

def test_notifications_reach_slack_and_sms_webhooks_and_retry_on_failure(engine, node, client, pol, monkeypatch):
    import http.server

    received = []

    class Hook(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["content-length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/"
    monkeypatch.setenv("SLACK_WEBHOOK_URL", url)
    monkeypatch.setenv("SMS_WEBHOOK_URL", "http://127.0.0.1:9/nothing-listens-here")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    send(client, ["ids: BREACH"])
    Analytics(engine, pol).tick()
    worker = RecoveryEngine(engine, pol)
    worker.tick()
    assert worker.send_notifications() >= 1
    server.shutdown()
    assert any("Possible security breach" in r.get("text", "") for r in received)
    with engine.connect() as conn:
        rows = conn.execute(sa.select(db.notifications)).mappings().all()
    assert {r["status"] for r in rows if r["channel"] == "slack"} == {"sent"}
    sms = [r for r in rows if r["channel"] == "sms"]
    assert sms and all(r["status"] == "pending" and r["attempts"] == 1 and r["last_error"] for r in sms)


def test_email_channel_builds_the_message(monkeypatch):
    from sentinel.services import recovery as recovery_mod

    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["host"] = host

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self, context):
            sent["tls"] = True

        def send_message(self, message):
            sent["to"] = message["To"]
            sent["subject"] = message["Subject"]

    monkeypatch.setattr(recovery_mod.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("SMTP_HOST", "smtp.example.org")
    monkeypatch.setenv("ALERT_EMAIL_TO", "team@example.org")
    recovery_mod.deliver("email", "Subject here", "Body")
    assert sent == {"host": "smtp.example.org", "tls": True, "to": "team@example.org", "subject": "Subject here"}


def test_new_breach_still_gets_fresh_evidence_within_the_cooldown(engine, node, client, pol):
    send(client, ["sshd: Failed password for root from 203.0.113.9 port 1 ssh2"] * 9)
    Analytics(engine, pol).tick()
    RecoveryEngine(engine, pol).tick()
    send(client, ["ids: BREACH"])
    Analytics(engine, pol).tick()
    RecoveryEngine(engine, pol).tick()
    assert [a["action"] for a in actions_of(engine)].count("preserve_evidence") == 2


def test_sudo_mode_passes_the_mode_as_an_argument(tmp_path, monkeypatch):
    from sentinel.agent import daemon

    seen = {}

    class Done:
        returncode, stdout, stderr = 0, "ok", ""

    def fake_run(command, **kwargs):
        seen["command"] = command
        return Done()

    monkeypatch.setattr(daemon.subprocess, "run", fake_run)
    agent = make_agent(tmp_path, use_sudo=True, recovery_mode="enforce")
    assert agent.run_action({"action": "restart_service", "arg": "nginx"})["dry_run"] is False
    assert seen["command"] == ["sudo", "-n", SCRIPT, "--enforce", "restart_service", "nginx"]
    agent = make_agent(tmp_path, use_sudo=True)
    agent.run_action({"action": "clear_cache"})
    assert seen["command"] == ["sudo", "-n", SCRIPT, "--dry-run", "clear_cache"]


def test_backup_runs_for_real_and_keeps_only_seven(tmp_path):
    source = tmp_path / "important"
    source.mkdir()
    (source / "file").write_text("data")
    backups = tmp_path / "backups"
    backups.mkdir()
    for i in range(8):
        old = backups / f"backup-2020010{i}T000000Z.tar.gz"
        old.write_text("old")
        os.utime(old, (1_600_000_000 + i, 1_600_000_000 + i))
    out = rec(tmp_path, "--enforce", "backup_snapshot", SENTINEL_TEST_BACKUP_PATHS=str(source))
    assert out.returncode == 0, out.stderr
    archives = sorted(backups.glob("backup-*.tar.gz"))
    assert len(archives) == 7
    newest = max(archives, key=lambda p: p.stat().st_mtime)
    listing = subprocess.run(["tar", "-tzf", str(newest)], capture_output=True, text=True).stdout
    assert "important/file" in listing
    assert subprocess.run(["sha256sum", "-c", f"{newest}.sha256"], capture_output=True).returncode == 0


def test_drill_hazard_command_reaches_the_correlation_engine(engine, node, client, pol):
    env = {**os.environ, "DATABASE_URL": str(engine.url.render_as_string(hide_password=False)), "PYTHONPATH": str(ROOT / "src")}
    out = subprocess.run(["python3", "-m", "sentinel.admin", "drill-hazard", "--lat", "13.2", "--lon", "80.5"],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    send(client, ["systemd: nginx.service: Failed with result"])
    Analytics(engine, pol).tick()
    inc = {i["category"]: i for i in incidents_of(engine)}
    assert inc["hazard_infrastructure"]["severity"] == "HIGH"
    assert "DRILL" in inc["hazard_infrastructure"]["summary"]
