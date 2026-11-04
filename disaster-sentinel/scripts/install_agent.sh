#!/usr/bin/env bash
# Install the edge agent on a Linux node as a systemd service. Run as root.
#   sudo ./scripts/install_agent.sh --server https://SERVER:8444 --token TOKEN --ca deploy/certs/ca.crt
# It starts in simulation mode. Nothing on the machine changes until you set
# "recovery_mode": "enforce" in /etc/sentinel/agent.json.
set -euo pipefail

SERVER="" TOKEN="" CA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER=$2; shift 2 ;;
    --token) TOKEN=$2; shift 2 ;;
    --ca) CA=$2; shift 2 ;;
    *) echo "Unknown option $1" >&2; exit 64 ;;
  esac
done
[[ -n "$SERVER" && -n "$TOKEN" ]] || { echo "--server and --token are required" >&2; exit 64; }
[[ $EUID -eq 0 ]] || { echo "Run this as root" >&2; exit 77; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"

id sentinel >/dev/null 2>&1 || useradd --system --home /var/lib/sentinel --shell /usr/sbin/nologin sentinel
# The adm group lets the agent read /var/log/syslog and auth.log, systemd-journal the journal.
usermod -aG adm sentinel 2>/dev/null || true
usermod -aG systemd-journal sentinel 2>/dev/null || true

install -d -o root -g root -m 755 /opt/sentinel /opt/sentinel/lib/sentinel/agent /etc/sentinel
install -d -o sentinel -g sentinel -m 700 /var/lib/sentinel /var/lib/sentinel/spool
python3 -m venv /opt/sentinel/venv
/opt/sentinel/venv/bin/pip install --quiet -r "$HERE/requirements/agent.txt"
install -o root -g root -m 644 "$HERE/src/sentinel/__init__.py" /opt/sentinel/lib/sentinel/
install -o root -g root -m 644 "$HERE/src/sentinel/agent/__init__.py" "$HERE/src/sentinel/agent/daemon.py" /opt/sentinel/lib/sentinel/agent/
# Root-owned and not writable by the agent: this script runs as root through sudo.
install -o root -g root -m 755 "$HERE/scripts/recovery.sh" /opt/sentinel/recovery.sh
[[ -f /etc/sentinel/recovery.conf ]] || install -o root -g root -m 644 "$HERE/deploy/recovery.conf.example" /etc/sentinel/recovery.conf

umask 077
printf '%s\n' "$TOKEN" > /etc/sentinel/token
chown sentinel:sentinel /etc/sentinel/token
if [[ -n "$CA" ]]; then install -o root -g root -m 644 "$CA" /etc/sentinel/ca.crt; fi
if [[ ! -f /etc/sentinel/agent.json ]]; then
  sed -e "s#__SERVER__#$SERVER#" "$HERE/deploy/agent.example.json" > /etc/sentinel/agent.json
  chown root:sentinel /etc/sentinel/agent.json
  chmod 640 /etc/sentinel/agent.json
fi

# sudo may run this one script as root and nothing else.
printf 'sentinel ALL=(root) NOPASSWD: /opt/sentinel/recovery.sh *\n' > /etc/sudoers.d/sentinel-agent
chmod 440 /etc/sudoers.d/sentinel-agent
visudo -cf /etc/sudoers.d/sentinel-agent >/dev/null

install -o root -g root -m 644 "$HERE/deploy/systemd/sentinel-agent.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sentinel-agent
systemctl --no-pager --lines=3 status sentinel-agent || true
echo "Agent installed in simulation mode. Edit /etc/sentinel/agent.json to change that."
