#!/usr/bin/env bash
# First-time setup: random secrets in .env, a local CA and server certificate, data folders.
# Needs only bash and openssl, so it also works in Git Bash on Windows.
# Safe to run again. Existing secrets and certificates are kept, and missing or blank
# secrets are filled in.
set -euo pipefail
cd "$(dirname "$0")/.."

SERVER_NAMES=${1:-localhost}   # Comma-separated names or IPs agents will use to reach the server.

command -v openssl >/dev/null || { echo "openssl is required. Install it and run this again." >&2; exit 69; }

SECRETS="DB_OWNER_PASSWORD SENTINEL_INGEST_PASSWORD SENTINEL_ANALYTICS_PASSWORD SENTINEL_HAZARDS_PASSWORD
SENTINEL_RECOVERY_PASSWORD SENTINEL_DASHBOARD_PASSWORD AUDIT_HMAC_KEY SESSION_SECRET CLASSIFIER_TOKEN OPERATOR_PASSWORD"

secret() {
  local value
  value=$(openssl rand -hex 32)
  [[ ${#value} -eq 64 ]] || { echo "openssl could not generate a secret" >&2; exit 70; }
  printf '%s' "$value"
}

# Set a key only if it is missing or blank, leaving every other line untouched.
fill() {
  local key=$1 value=$2
  if ! grep -q "^$key=." .env; then
    grep -v "^$key=" .env > .env.tmp || true
    printf '%s=%s\n' "$key" "$value" >> .env.tmp
    mv .env.tmp .env
    added=$((added + 1))
  fi
}

umask 077
touch .env
added=0
for key in $SECRETS; do
  # A separate assignment, because set -e ignores a failure inside a command argument.
  value=$(secret)
  fill "$key" "$value"
done
# PostgreSQL cannot keep its data on a Windows folder, so it gets a Docker volume there.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) fill DB_DATA pgdata ;;
esac
umask 022
if [[ $added -gt 0 ]]; then
  echo "Wrote $added settings to .env. Your dashboard password is the OPERATOR_PASSWORD line in that file."
else
  echo ".env is complete, keeping it."
fi

mkdir -p data/postgres deploy/certs
if [[ ! -f deploy/certs/server.crt ]]; then
  # DNS:ingest lets the demo agent container reach the ingest container.
  san="DNS:localhost,DNS:ingest,IP:127.0.0.1"
  IFS=',' read -ra names <<< "$SERVER_NAMES"
  for n in "${names[@]}"; do
    [[ "$n" == "localhost" || "$n" == "127.0.0.1" ]] && continue
    if [[ "$n" =~ ^[0-9.]+$ || "$n" == *:* ]]; then san+=",IP:$n"; else san+=",DNS:$n"; fi
  done
  # Names live in config files because Git Bash rewrites "/CN=..." arguments into Windows paths.
  cat > deploy/certs/ca.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = Disaster Sentinel local CA
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
  cat > deploy/certs/server.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = disaster-sentinel
EOF
  # Python 3.13 verifies strictly, so these extensions are required and not optional.
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n' "$san" > deploy/certs/server.ext

  openssl genrsa -out deploy/certs/ca.key 3072 2>/dev/null
  openssl req -x509 -new -key deploy/certs/ca.key -sha256 -days 825 \
    -config deploy/certs/ca.cnf -extensions v3_ca -out deploy/certs/ca.crt
  openssl genrsa -out deploy/certs/server.key 2048 2>/dev/null
  openssl req -new -key deploy/certs/server.key -config deploy/certs/server.cnf -out deploy/certs/server.csr
  openssl x509 -req -in deploy/certs/server.csr -CA deploy/certs/ca.crt -CAkey deploy/certs/ca.key \
    -CAcreateserial -days 397 -sha256 -extfile deploy/certs/server.ext -out deploy/certs/server.crt 2>/dev/null
  rm -f deploy/certs/server.csr deploy/certs/server.ext deploy/certs/ca.cnf deploy/certs/server.cnf
  chmod 600 deploy/certs/ca.key
  # Containers run as an unprivileged user and must be able to read this development key.
  chmod 644 deploy/certs/server.key
  echo "Created certificates for: $san"
else
  echo "Certificates already exist, keeping them."
fi

if ! docker compose version >/dev/null 2>&1 && ! podman compose version >/dev/null 2>&1; then
  echo "Next: install Docker Desktop (or Podman) and start it, then run: docker compose up -d --build"
else
  echo "Next: docker compose up -d --build"
fi
