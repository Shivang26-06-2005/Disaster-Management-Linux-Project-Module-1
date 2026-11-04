"""Edge node daemon (slide 13, model 4). Standard library plus psutil, to stay small.

    python -m sentinel.agent.daemon --config /etc/sentinel/agent.json

* Metrics are sampled and logs tailed locally, then sent over outbound HTTPS.
* Batches are spooled to disk first, because a disaster is exactly when the network
  fails. They are sent oldest first when the connection returns.
* Recovery actions are re-checked here against a local allowlist. The server can ask,
  but only this file decides what may run on this machine.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path

import psutil

VERSION = "1.0.0"
log = logging.getLogger("sentinel-agent")

DEFAULT_ACTIONS = ["preserve_evidence", "backup_snapshot", "clear_cache", "restart_service", "isolate_ip"]
_SERVICE = re.compile(r"^[A-Za-z0-9@._-]{1,120}$")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Tailer:
    """Follow a log file from its end, and survive rotation and truncation."""

    def __init__(self, path: str):
        self.path = path
        self._fh = None
        self._inode = None
        self._partial = ""

    def _open(self, seek_end: bool) -> bool:
        try:
            fh = open(self.path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return False
        if seek_end:
            fh.seek(0, os.SEEK_END)
        self._fh, self._inode = fh, os.fstat(fh.fileno()).st_ino
        return True

    def read_lines(self, limit: int = 2000) -> list[str]:
        if self._fh is None and not self._open(seek_end=self._inode is None):
            return []
        lines: list[str] = []
        while len(lines) < limit:
            chunk = self._fh.readline()
            if not chunk:
                break
            if not chunk.endswith("\n"):
                self._partial += chunk
                break
            lines.append((self._partial + chunk).rstrip("\n"))
            self._partial = ""
        if not lines:
            try:
                stat = os.stat(self.path)
                if stat.st_ino != self._inode or stat.st_size < self._fh.tell():
                    self._fh.close()
                    self._fh = None
                    self._partial = ""
                    self._open(seek_end=False)
            except OSError:
                self._fh.close()
                self._fh = None
        return lines


class JournalReader(threading.Thread):
    """Used on systems with no /var/log/syslog, such as a default Ubuntu 24.04 desktop."""

    def __init__(self, buffer: deque):
        super().__init__(daemon=True)
        self.buffer = buffer

    def run(self) -> None:
        while True:
            try:
                proc = subprocess.Popen(
                    ["journalctl", "-f", "-n", "0", "-o", "short-iso", "--no-pager"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace",
                )
                for line in proc.stdout:
                    self.buffer.append({"ts": utcnow(), "source": "journald", "line": line.rstrip("\n")[:8000]})
            except OSError as exc:
                log.warning("journalctl unavailable: %s", exc)
                return
            time.sleep(5)


class Spool:
    """Bounded on-disk queue. When full, the oldest batches are dropped and counted."""

    def __init__(self, directory: Path, max_batches: int):
        self.dir = directory
        self.max = max_batches
        self.dropped = 0
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)

    def put(self, batch: dict) -> None:
        name = f"{time.time_ns():020d}-{batch['batch_id']}.json"
        tmp = self.dir / f".{name}"
        tmp.write_text(json.dumps(batch))
        tmp.rename(self.dir / name)
        files = self.files()
        for old in files[: max(0, len(files) - self.max)]:
            old.unlink(missing_ok=True)
            self.dropped += 1

    def files(self) -> list[Path]:
        return sorted(self.dir.glob("[0-9]*.json"))


class Agent:
    def __init__(self, config: dict):
        self.cfg = config
        self.server = config["server"].rstrip("/")
        self.token = (
            os.environ.get("SENTINEL_AGENT_TOKEN")
            or config.get("token")
            or Path(config["token_file"]).read_text().strip()
        )
        self.interval = float(config.get("interval_s", 5))
        self.send_every = float(config.get("send_every_s", 10))
        self.mode = config.get("recovery_mode", "dry_run")
        if self.mode not in {"dry_run", "enforce"}:
            raise ValueError("recovery_mode must be dry_run or enforce")
        self.allowed_actions = set(config.get("allowed_actions", DEFAULT_ACTIONS))
        self.allowed_services = set(config.get("allowed_services", []))
        self.protected_cidrs = [ip_network(c) for c in config.get("protected_cidrs", [
            "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fe80::/10",
        ])]
        self.allow_isolate = bool(config.get("allow_isolate", False))
        self.recovery_script = config.get("recovery_script", "/opt/sentinel/recovery.sh")
        self.use_sudo = bool(config.get("use_sudo", False))
        self.disk_path = config.get("disk_path", "/")
        self.log_files = config.get("log_files", ["/var/log/syslog", "/var/log/auth.log"])
        self.max_lines = int(config.get("max_lines_per_batch", 5000))
        self.spool = Spool(Path(config.get("spool_dir", "/var/lib/sentinel/spool")),
                           int(config.get("spool_max_batches", 8640)))
        self.tailers = [Tailer(p) for p in self.log_files if os.path.exists(p)]
        self.journal: deque = deque(maxlen=self.max_lines)
        self.journal_reader = None
        if not self.tailers and config.get("use_journal_if_no_files", True) and shutil.which("journalctl"):
            self.journal_reader = JournalReader(self.journal)
        self.metrics: list[dict] = []
        self.logs: list[dict] = []
        self.lines_dropped = 0
        self.proc = psutil.Process()
        self.proc.cpu_percent(None)
        psutil.cpu_percent(None)
        time.sleep(0.5)  # The first reading covers almost no time and can show a false 100%.
        self.ssl_context = None
        if self.server.startswith("https://"):
            self.ssl_context = ssl.create_default_context(cafile=config.get("ca_file"))
        self._stop = threading.Event()
        self._last_ntp = (0.0, None)

    # Telemetry -------------------------------------------------------------------

    def sample(self) -> None:
        disk = psutil.disk_usage(self.disk_path).percent
        self.metrics.append({
            "ts": utcnow(), "cpu": psutil.cpu_percent(None), "mem": psutil.virtual_memory().percent,
            "disk": disk, "load1": os.getloadavg()[0],
        })

    def read_logs(self) -> None:
        for tailer in self.tailers:
            for line in tailer.read_lines():
                if len(self.logs) >= self.max_lines:
                    self.lines_dropped += 1
                    continue
                self.logs.append({"ts": utcnow(), "source": tailer.path, "line": line[:8000]})
        while self.journal and len(self.logs) < self.max_lines:
            self.logs.append(self.journal.popleft())

    def _ntp_synced(self) -> bool | None:
        at, value = self._last_ntp
        if time.time() - at < 300:
            return value
        value = None
        if shutil.which("timedatectl"):
            try:
                out = subprocess.run(
                    ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                    capture_output=True, text=True, timeout=5,
                )
                if out.returncode == 0 and out.stdout.strip() in {"yes", "no"}:
                    value = out.stdout.strip() == "yes"
            except (OSError, subprocess.TimeoutExpired):
                pass
        self._last_ntp = (time.time(), value)
        return value

    def status(self) -> dict:
        sources = [t.path for t in self.tailers] + (["journald"] if self.journal_reader else [])
        return {
            "version": VERSION, "hostname": socket.gethostname(), "mode": self.mode,
            "recovery_ready": os.access(self.recovery_script, os.X_OK),
            "ntp_synced": self._ntp_synced(), "spooled": len(self.spool.files()),
            "dropped": self.spool.dropped + self.lines_dropped, "sources": sources,
            "self_cpu": self.proc.cpu_percent(None),
            "self_rss_mb": round(self.proc.memory_info().rss / 1048576, 1),
        }

    def flush_to_spool(self) -> None:
        if not self.metrics and not self.logs:
            return
        self.spool.put({"batch_id": str(uuid.uuid4()), "metrics": self.metrics, "logs": self.logs})
        self.metrics, self.logs = [], []

    # Network ---------------------------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        request = urllib.request.Request(
            self.server + path, data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"},
        )
        with urllib.request.urlopen(request, timeout=15, context=self.ssl_context) as response:
            return json.loads(response.read() or b"{}")

    def send_spool(self) -> bool:
        for path in self.spool.files()[:50]:
            try:
                batch = json.loads(path.read_text())
            except (OSError, ValueError):
                path.unlink(missing_ok=True)
                continue
            batch["sent_at"] = utcnow()
            batch["status"] = self.status()
            try:
                self._post("/v1/telemetry", batch)
            except urllib.error.HTTPError as exc:
                if exc.code in {400, 413, 422}:
                    log.error("Server rejected a batch with HTTP %s. Dropping it.", exc.code)
                    path.unlink(missing_ok=True)
                    self.spool.dropped += 1
                    continue
                log.warning("Server returned HTTP %s. Keeping the batch.", exc.code)
                return False
            except (urllib.error.URLError, OSError) as exc:
                log.warning("Server unreachable (%s). Keeping %s batches.", exc, len(self.spool.files()))
                return False
            path.unlink(missing_ok=True)
        return True

    # Recovery --------------------------------------------------------------------

    def check_action(self, action: str, arg: str | None) -> str | None:
        """Return why an action must not run, or None. This is the node's own decision."""
        if action not in self.allowed_actions:
            return f"{action} is not in this node's allowed_actions"
        if action == "restart_service":
            if not arg or not _SERVICE.match(arg):
                return "Invalid service name"
            if arg not in self.allowed_services:
                return f"{arg} is not in this node's allowed_services"
        elif action == "isolate_ip":
            if not self.allow_isolate:
                return "allow_isolate is off on this node"
            try:
                address = ip_address(arg or "")
            except ValueError:
                return "Invalid IP address"
            if any(address in net for net in self.protected_cidrs if net.version == address.version):
                return f"{address} is in a protected network range"
        elif arg:
            return f"{action} takes no target"
        return None

    def run_action(self, item: dict) -> dict:
        action, arg = item["action"], item.get("arg")
        dry_run = self.mode != "enforce"
        refusal = self.check_action(action, arg)
        if refusal:
            log.warning("Refused %s %s: %s", action, arg, refusal)
            return {"exit_code": 126, "dry_run": dry_run, "output": f"Refused by node policy: {refusal}"}
        # The mode is an explicit argument because sudo resets the environment.
        flag = "--dry-run" if dry_run else "--enforce"
        command = [self.recovery_script, flag, action] + ([arg] if arg else [])
        if self.use_sudo:
            command = ["sudo", "-n", *command]
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
        env.update({k: v for k, v in os.environ.items() if k.startswith("SENTINEL_TEST_") or k == "SENTINEL_RECOVERY_TEST_ROOT"})
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=300, env=env, errors="replace")
            return {"exit_code": done.returncode, "dry_run": dry_run,
                    "output": (done.stdout + done.stderr)[-20000:]}
        except subprocess.TimeoutExpired:
            return {"exit_code": 124, "dry_run": dry_run, "output": "Timed out after 300 seconds"}
        except OSError as exc:
            return {"exit_code": 127, "dry_run": dry_run, "output": f"Could not start recovery script: {exc}"}

    def poll_actions(self) -> None:
        try:
            actions = self._post("/v1/actions/claim", {}).get("actions", [])
        except (urllib.error.URLError, OSError) as exc:
            log.debug("Could not poll actions: %s", exc)
            return
        for item in actions:
            outcome = self.run_action(item)
            log.info("Action %s %s exited %s (dry run: %s)", item["action"], item.get("arg"),
                     outcome["exit_code"], outcome["dry_run"])
            try:
                self._post(f"/v1/actions/{item['id']}/result", outcome)
            except (urllib.error.URLError, OSError) as exc:
                log.warning("Could not report action result: %s", exc)

    # Main loop -------------------------------------------------------------------

    def stop(self, *_: object) -> None:
        self._stop.set()

    def run(self) -> None:
        if self.journal_reader:
            self.journal_reader.start()
        log.info("Agent %s started in %s mode, sources: %s", VERSION, self.mode,
                 [t.path for t in self.tailers] or ("journald" if self.journal_reader else "none"))
        last_send = 0.0
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.sample()
                self.read_logs()
                if time.monotonic() - last_send >= self.send_every:
                    self.flush_to_spool()
                    if self.send_spool():
                        self.poll_actions()
                    last_send = time.monotonic()
            except Exception:  # The daemon must outlive any single bad cycle.
                log.exception("Agent cycle failed, continuing")
            self._stop.wait(max(0.0, self.interval - (time.monotonic() - started)))
        self.flush_to_spool()
        log.info("Agent stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="Disaster Sentinel edge agent")
    parser.add_argument("--config", default=os.environ.get("SENTINEL_AGENT_CONFIG", "/etc/sentinel/agent.json"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s sentinel-agent: %(levelname)s %(message)s")
    agent = Agent(json.loads(Path(args.config).read_text()))
    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    agent.run()


if __name__ == "__main__":
    main()
