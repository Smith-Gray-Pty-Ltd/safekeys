#!/usr/bin/env bash
#
# Start the Safekeys development stack: control plane + sidecar.
#
# Creates a stable dev signing key under .dev/ so that issued tokens survive
# a restart. The KEK is NOT stored in a plaintext file: per
# .usm/features/resolution/dev-key-custody.usm the default custody ladder is
#
#   1. SAFEKEYS_VAULT_ADDR set → OpenBao/Vault transit (started here if needed)
#   2. macOS → the macOS Keychain, ACL-restricted to the sidecar binary
#   3. Linux without a vault → the containerised dev OpenBao (this script
#      starts it)
#
# A plaintext KEK file appears ONLY behind an explicit opt-in
# (SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1) and the sidecar then warns loudly that
# the mode is not for real secrets.
#
# Usage:
#   ./scripts/dev-up.sh          # start in the foreground
#   ./scripts/dev-up.sh --daemon # start in the background, log to .dev/
#   ./scripts/dev-down.sh        # stop
#
# NEVER use this in production. It sets development-only variables and runs
# OpenBao in dev mode with a fixed root token — exactly what
# deploy/ exists to replace.
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

export SAFEKEYS_KID="${SAFEKEYS_KID:-dev-key-1}"
export DATABASE_URL="${DATABASE_URL:-postgres://safekeys:safekeys-dev-password@localhost:5432/safekeys?sslmode=disable}"
export SAFEKEYS_ISSUER="${SAFEKEYS_ISSUER:-https://cp.safekeys.local}"
export SAFEKEYS_ADDR="${SAFEKEYS_ADDR:-:8080}"

# Shared settings — the socket path, API key, control-plane URL, audience,
# keystore and folder. Defined once in scripts/lib/common.sh so dev-up.sh,
# dev-down.sh and demo.sh cannot disagree about where the sidecar listens.
# shellcheck source=lib/common.sh
source "$ROOT/scripts/lib/common.sh"

# ── KEK custody (dev-key-custody) ────────────────────────────────────────────
#
# The default is: the KEK lives in OpenBao transit (dev container) or the
# macOS Keychain. A plaintext .dev/kek is created ONLY when the operator has
# explicitly demanded it.
INSECURE_KEYFILE="${SAFEKEYS_ALLOW_INSECURE_KEYSTORE:-}"
if [[ -n "$INSECURE_KEYFILE" && "$INSECURE_KEYFILE" != "1" ]]; then
  echo "SAFEKEYS_ALLOW_INSECURE_KEYSTORE must be 1 or unset (got '$INSECURE_KEYFILE')" >&2
  exit 1
fi

if [[ "$INSECURE_KEYFILE" == "1" ]]; then
  echo "======================================================================" >&2
  echo "WARNING: plaintext key-file mode requested (SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1)." >&2
  echo "WARNING: the KEK will live in a file your coding agent's OS user can read." >&2
  echo "WARNING: this mode is NOT FOR REAL SECRETS. Prefer the default (Keychain" >&2
  echo "WARNING: on macOS, OpenBao dev container otherwise)." >&2
  echo "======================================================================" >&2
  export SAFEKEYS_KEYSTORE="${SAFEKEYS_KEYSTORE:-$SAFEKEYS_DEV_DIR/kek}"
  export SAFEKEYS_KEYCHAIN=0
  unset SAFEKEYS_VAULT_ADDR
else
  # Stale plaintext key material from the pre-custody flow must not sit
  # readable while the opt-in is off (dev-key-custody, insecure-file-strict
  # by implication: the default flow leaves no readable key file). Refuse and
  # print the one-line fix.
  for stale in "$SAFEKEYS_DEV_DIR/kek" "$SAFEKEYS_DEV_DIR/dev-signing-key"; do
    if [[ -f "$stale" ]]; then
      echo "refusing to start: stale plaintext key material at $stale" >&2
      echo "run:  ./scripts/migrate-dev-keys.sh   # re-wraps objects and deletes it" >&2
      echo "or:   export SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1  # keep the file (not for real secrets)" >&2
      exit 1
    fi
  done
  # macOS default: Keychain custody. No plaintext file, no vault needed.
  if [[ "${SAFEKEYS_KEYCHAIN:-0}" == "1" ]]; then
    unset SAFEKEYS_VAULT_ADDR
    echo "KEK custody: macOS Keychain (ACL restricted to the sidecar binary)"
    echo "Signing seed: macOS Keychain (migrated by scripts/migrate-dev-keys.sh)"
  else
    # Linux (or macOS with keychain disabled): the containerised dev OpenBao.
    export SAFEKEYS_VAULT_TOKEN="${SAFEKEYS_VAULT_TOKEN:-root}"
    if ! docker compose -f "$ROOT/docker-compose.yml" ps --status running --format '{{.Name}}' 2>/dev/null | grep -q openbao; then
      echo "Starting the dev OpenBao (key custody; transit key and signing seed are created once)…"
      docker compose -f "$ROOT/docker-compose.yml" up -d openbao openbao-init >/dev/null
      for _ in $(seq 1 60); do
        curl -sf -H "X-Vault-Token: root" "$SAFEKEYS_VAULT_ADDR/v1/sys/health" >/dev/null 2>&1 && break
        sleep 0.5
      done
      docker compose -f "$ROOT/docker-compose.yml" up openbao-init >/dev/null 2>&1 || true
    fi
    echo "KEK custody: OpenBao transit at $SAFEKEYS_VAULT_ADDR (key ${SAFEKEYS_VAULT_KID:-kek-1})"
    # Signing seed: generated once into OpenBao KV and fetched from there at
    # start — no plaintext seed file exists. It still travels through the
    # process environment (readable via /proc by the same user), which is a
    # documented dev-only limitation; production delivers it as a root-owned
    # credential (deployment-packaging) and Phase 1 moves it into hardware.
    if ! curl -sf -H "X-Vault-Token: $SAFEKEYS_VAULT_TOKEN" \
        "$SAFEKEYS_VAULT_ADDR/v1/secret/data/safekeys/dev-signing-key" \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["data"]["seed"])' \
        > /dev/null 2>&1; then
      python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())' \
        | curl -sf -X POST -H "X-Vault-Token: $SAFEKEYS_VAULT_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$(python3 -c 'import json,sys;print(json.dumps({"data":{"seed":sys.stdin.read().strip()}}))')" \
            "$SAFEKEYS_VAULT_ADDR/v1/secret/data/safekeys/dev-signing-key" >/dev/null
      echo "generated a new development signing seed in OpenBao KV (secret/safekeys/dev-signing-key)"
    fi
    SAFEKEYS_DEV_SIGNING_KEY="$(curl -sf -H "X-Vault-Token: $SAFEKEYS_VAULT_TOKEN" \
      "$SAFEKEYS_VAULT_ADDR/v1/secret/data/safekeys/dev-signing-key" \
      | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["data"]["seed"])')"
    export SAFEKEYS_DEV_SIGNING_KEY
  fi
fi

# ── Stable dev credentials ───────────────────────────────────────────────────
# The signing seed is NOT written to a plaintext file: per dev-key-custody it
# lives in the Keychain (macOS) after migration, or is supplied by the
# environment for one-off bootstrap. A seed file is created only when the
# operator has explicitly opted into insecure file mode.
if [[ "$INSECURE_KEYFILE" == "1" ]]; then
  KEYFILE="$DEV/dev-signing-key"
  if [[ ! -f "$KEYFILE" ]]; then
    python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())' > "$KEYFILE"
    chmod 600 "$KEYFILE"
    echo "generated a new development signing key at $KEYFILE"
  fi
  SAFEKEYS_DEV_SIGNING_KEY="$(cat "$KEYFILE")"
  export SAFEKEYS_DEV_SIGNING_KEY
fi

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
  if [[ -n "${SAFEKEYS_VAULT_ADDR:-}" ]]; then
    echo "  export SAFEKEYS_VAULT_ADDR=$SAFEKEYS_VAULT_ADDR"
    echo "  export SAFEKEYS_VAULT_TOKEN=$SAFEKEYS_VAULT_TOKEN"
  elif [[ "${SAFEKEYS_KEYCHAIN:-0}" == "1" ]]; then
    echo "  export SAFEKEYS_KEYCHAIN=1"
  else
    echo "  export SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1"
    echo "  export SAFEKEYS_KEYSTORE=$SAFEKEYS_KEYSTORE"
  fi
  echo "  export SAFEKEYS_FOLDER=$SAFEKEYS_FOLDER"
  echo "  export SAFEKEYS_AUDIENCE=$SAFEKEYS_AUDIENCE"
  exit 0
fi

trap 'kill 0' INT TERM
"$ROOT/bin/safekeys-cp" &
sleep 1
"$ROOT/bin/safekeys-sidecar" &
wait