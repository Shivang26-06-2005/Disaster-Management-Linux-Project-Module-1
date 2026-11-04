"""setup.sh must work with only bash and openssl, including in Git Bash on Windows."""
import os
import shutil
import ssl
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REAL = ["bash", "openssl", "mkdir", "dirname", "cat", "grep", "mv", "rm", "chmod", "touch", "uname", "cut", "tail", "tr", "sed", "env"]


@pytest.fixture()
def project(tmp_path):
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts" / "setup.sh", tmp_path / "scripts" / "setup.sh")
    # A PATH holding only the basic tools: no python3, no docker.
    tools = tmp_path / "bin"
    tools.mkdir()
    for name in REAL:
        (tools / name).symlink_to(shutil.which(name))
    return tmp_path


def run(project, *args):
    env = {"PATH": str(project / "bin"), "HOME": str(project)}
    return subprocess.run(["bash", str(project / "scripts" / "setup.sh"), *args], capture_output=True, text=True, env=env)


def read_env(project):
    return dict(line.split("=", 1) for line in (project / ".env").read_text().splitlines())


SECRETS = ["DB_OWNER_PASSWORD", "SENTINEL_INGEST_PASSWORD", "SENTINEL_ANALYTICS_PASSWORD", "SENTINEL_HAZARDS_PASSWORD",
           "SENTINEL_RECOVERY_PASSWORD", "SENTINEL_DASHBOARD_PASSWORD", "AUDIT_HMAC_KEY", "SESSION_SECRET",
           "CLASSIFIER_TOKEN", "OPERATOR_PASSWORD"]


def test_works_without_python_and_every_secret_is_real_and_distinct(project):
    out = run(project)
    assert out.returncode == 0, out.stderr
    env = read_env(project)
    assert all(len(env[k]) >= 32 for k in SECRETS)
    assert len({env[k] for k in SECRETS}) == len(SECRETS)
    assert stat.S_IMODE((project / ".env").stat().st_mode) == 0o600
    assert "Next:" in out.stdout


def test_blank_secrets_from_the_old_script_are_repaired(project):
    (project / ".env").write_text("".join(f"{k}=\n" for k in SECRETS) + "SMTP_HOST=\n")
    assert run(project).returncode == 0
    env = read_env(project)
    assert all(len(env[k]) >= 32 for k in SECRETS)
    assert env["SMTP_HOST"] == ""
    assert (project / ".env").read_text().count("OPERATOR_PASSWORD=") == 1


def test_second_run_keeps_secrets_and_certificates(project):
    run(project)
    before, cert = read_env(project), (project / "deploy/certs/server.crt").read_bytes()
    out = run(project)
    assert out.returncode == 0 and read_env(project) == before
    assert (project / "deploy/certs/server.crt").read_bytes() == cert


def test_half_finished_certificate_run_recovers(project):
    (project / "deploy/certs").mkdir(parents=True)
    (project / "deploy/certs/ca.key").write_text("left over from a failed run")
    assert run(project).returncode == 0
    assert (project / "deploy/certs/server.crt").exists()


def test_failed_secret_generation_stops_with_no_blank_values(project):
    fake = project / "bin" / "openssl"
    fake.unlink()
    fake.write_text("#!/bin/bash\nexit 1\n")
    fake.chmod(0o755)
    out = run(project)
    assert out.returncode != 0
    assert "OPERATOR_PASSWORD=" not in (project / ".env").read_text()


@pytest.mark.parametrize("name,expected", [("MINGW64_NT-10.0-26100", True), ("MSYS_NT-10.0", True), ("Linux", False)])
def test_windows_gets_a_docker_volume_for_the_database(project, name, expected):
    fake = project / "bin" / "uname"
    fake.unlink()
    fake.write_text(f"#!/bin/bash\necho {name}\n")
    fake.chmod(0o755)
    assert run(project).returncode == 0
    assert (read_env(project).get("DB_DATA") == "pgdata") is expected


def test_no_openssl_argument_looks_like_a_path_git_bash_would_rewrite():
    assert "-subj" not in (ROOT / "scripts" / "setup.sh").read_text()


def test_certificate_passes_python_strict_verification_for_all_names(project):
    assert run(project, "localhost,192.168.1.50,server.lan").returncode == 0
    certs = project / "deploy" / "certs"
    context = ssl.create_default_context(cafile=str(certs / "ca.crt"))
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    text = subprocess.run(["openssl", "x509", "-in", str(certs / "server.crt"), "-noout", "-ext", "subjectAltName"],
                          capture_output=True, text=True).stdout
    for name in ("DNS:localhost", "DNS:ingest", "IP Address:127.0.0.1", "IP Address:192.168.1.50", "DNS:server.lan"):
        assert name in text
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(certs / "server.crt", certs / "server.key")
    a, b = ssl.MemoryBIO(), ssl.MemoryBIO()
    c, d = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_side = context.wrap_bio(a, b, server_hostname="ingest")
    server_side = server.wrap_bio(c, d, server_side=True)
    for _ in range(10):
        for side, out_bio, in_bio in ((client_side, b, c), (server_side, d, a)):
            try:
                side.do_handshake()
            except ssl.SSLWantReadError:
                pass
            if out_bio.pending:
                in_bio.write(out_bio.read())
    assert client_side.version() is not None


@pytest.mark.parametrize("name", ["setup.sh", "demo.sh", "recovery.sh", "install_agent.sh"])
def test_scripts_are_executable(name):
    assert os.access(ROOT / "scripts" / name, os.X_OK)
