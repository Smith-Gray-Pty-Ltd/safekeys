#!/usr/bin/env bash
#
# Start the Safekeys development stack: control plane + sidecar.
#
# Creates a stable dev signing key and KEK under .dev/ so that tokens and folders
# survive a restart — otherwise every restart would invalidate issued tokens.
#
# Usage:
#   ./scripts/dev-up.sh          # start in the foreground
#   ./scripts/dev-up.sh --daemon # start in the background, log to .dev/
#   ./scripts/dev-down.sh        # stop
#
# NEVER use this in production. It sets SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1,
# which keeps the KEK in a file on disk — exactly the exposure the Vault
# implementation and Phase 1 hardware exist to eliminate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="$ROOT/.dev"
mkdir -p "$DEV"

DAEMON=0
[[ "${1:-}" == "--daemon" ]] && DAEMON=1

# ── Prerequisites ────────────────────────────────────────────────────────────
if ! docker compose -f "$ROOT/docker-compose.yml" ps --status running --format '{{.Name}}' 2>/dev/null | grep -q postgres; then
  echo "Postgres is not running. Start it with: docker compose up -d" >&2
  exit 1
fi
for b in safekeys safekeys-cp safekeys-sidecar; do
  if [[ ! -x "$ROOT/bin/$b" ]]; then
    echo "bin/$b missing. Build with: make build" >&2
    exit 1
  fi
done

# ── Stable dev credentials ───────────────────────────────────────────────────
# Generated once and reused, so restarts do not invalidate existing tokens.
KEYFILE="$DEV/dev-signing-key"
if [[ ! -f "$KEYFILE" ]]; then
  python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())' > "$KEYFILE"
  chmod 600 "$KEYFILE"
  echo "generated a new development signing key at $KEYFILE"
fi

export SAFEKEYS_DEV_SIGNING_KEY="$(cat "$KEYFILE")"
export SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1
export SAFEKEYS_API_KEY="${SAFEKEYS_API_KEY:-dev-api-key}"
export SAFEKEYS_KID="${SAFEKEYS_KID:-dev-key-1}"
export DATABASE_URL="${DATABASE_URL:-postgres://safekeys:safekeys-dev-password@localhost:5432/safekeys?sslmode=disable}"
export SAFEKEYS_ISSUER="${SAFEKEYS_ISSUER:-https://cp.safekeys.local}"
export SAFEKEYS_ADDR="${SAFEKEYS_ADDR:-:8080}"
export SAFEKEYS_CONTROL_PLANE_URL="${SAFEKEYS_CONTROL_PLANE_URL:-http://localhost:8080}"
export SAFEKEYS_AUDIENCE="${SAFEKEYS_AUDIENCE:-env-local}"
export SAFEKEYS_PRINCIPAL="${SAFEKEYS_PRINCIPAL:-operator}"
export SAFEKEYS_KEYSTORE="$DEV/kek"
export SAFEKEYS_FOLDER="$DEV/folder"
# Use the CONVENTIONAL socket path, which is what the Go, TypeScript and Python
# clients all default to ($TMPDIR/safekeys/sidecar.sock). Aligning them means the
# MCP server, SDK and CLI all find the sidecar with no environment configuration
# at all. Override SAFEKEYS_SOCKET for a non-default setup.
TMPBASE="${TMPDIR:-/tmp}"; TMPBASE="${TMPBASE%/}"
export SAFEKEYS_SOCKET="${SAFEKEYS_SOCKET:-$TMPBASE/safekeys/sidecar.sock}"
mkdir -p "$(dirname "$SAFEKEYS_SOCKET")"

# ── Start ────────────────────────────────────────────────────────────────────
if [[ $DAEMON -eq 1 ]]; then
  "$ROOT/bin/safekeys-cp"  > "$DEV/control-plane.log" 2>&1 &
  echo $! > "$DEV/control-plane.pid"
  for _ in $(seq 1 40); do
    curl -sf http://localhost:8080/healthz >/dev/null 2>&1 && break || sleep 0.25
  done
  "$ROOT/bin/safekeys-sidecar" > "$DEV/sidecar.log" 2>&1 &
  echo $! > "$DEV/sidecar.pid"
  for _ in $(seq 1 40); do
    [[ -S "$SAFEKEYS_SOCKET" ]] && break || sleep 0.25
  done
  echo "control plane:  http://localhost:8080   (log: .dev/control-plane.log)"
  echo "sidecar socket: $SAFEKEYS_SOCKET        (log: .dev/sidecar.log)"
  echo
  echo "Export these for the CLI / MCP server:"
  echo "  export SAFEKEYS_SOCKET=$SAFEKEYS_SOCKET"
  echo "  export SAFEKEYS_API_KEY=$SAFEKEYS_API_KEY"
  echo "  export SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1"
  echo "  export SAFEKEYS_KEYSTORE=$SAFEKEYS_KEYSTORE"
  echo "  export SAFEKEYS_FOLDER=$SAFEKEYS_FOLDER"
  echo "  export SAFEKEYS_AUDIENCE=$SAFEKEYS_AUDIENCE"
  exit 0
fi

trap 'kill 0' INT TERM
"$ROOT/bin/safekeys-cp" & 
sleep 1
"$ROOT/bin/safekeys-sidecar" &
wait
