#!/usr/bin/env bash
#
# Migrate dev key custody off the legacy plaintext files
# (safekeys/dev-key-custody): re-wrap every local-wrapped dev object under
# the new custody (macOS Keychain by default), then securely delete the old
# key files.
#
# Usage: ./scripts/migrate-dev-keys.sh [--insecure-keep-file]
#
# Without flags the migration target is the default custody for this host
# (Keychain on macOS, OpenBao transit otherwise). --insecure-keep-file
# migrates to the plaintext file mode instead (for machines that must keep
# the file; it still re-keys the file content).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="${SAFEKEYS_DEV_DIR:-$ROOT/.dev}"

KEEP_FILE=0
[[ "${1:-}" == "--insecure-keep-file" ]] && KEEP_FILE=1

# shellcheck source=lib/common.sh
source "$ROOT/scripts/lib/common.sh"

fail() { echo "migrate-dev-keys: $*" >&2; exit 1; }

[[ -x "$ROOT/bin/safekeys" ]] || fail "bin/safekeys missing — run make build"
[[ -f "$DEV/kek" ]] || fail "no $DEV/kek to migrate from (already migrated?)"

# ── Open the old (file) keystore and the new one ─────────────────────────────
OLD_KEK_FILE="$DEV/kek"

# The CLI exposes create/use through the sidecar; re-keying is a key-store
# operation, so do it with a tiny Go runner from the repo's own packages.
export SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1   # the OLD keystore needs it to open
if [[ $KEEP_FILE -eq 1 ]]; then
  export SAFEKEYS_KEYCHAIN=0
  export SAFEKEYS_VAULT_ADDR=""
  NEW_KID="kek-local-1"
else
  if [[ "$(uname -s)" == "Darwin" ]]; then
    export SAFEKEYS_KEYCHAIN=1
    unset SAFEKEYS_VAULT_ADDR
    NEW_KID="dev-key-1"
  else
    export SAFEKEYS_KEYCHAIN=0
    export SAFEKEYS_VAULT_ADDR="${SAFEKEYS_VAULT_ADDR:-http://localhost:8200}"
    export SAFEKEYS_VAULT_TOKEN="${SAFEKEYS_VAULT_TOKEN:-root}"
    docker compose -f "$ROOT/docker-compose.yml" up -d openbao openbao-init >/dev/null
    for _ in $(seq 1 60); do
      curl -sf -H "X-Vault-Token: $SAFEKEYS_VAULT_TOKEN" "$SAFEKEYS_VAULT_ADDR/v1/sys/health" >/dev/null 2>&1 && break
      sleep 0.5
    done
    NEW_KID="${SAFEKEYS_VAULT_KID:-kek-1}"
  fi
fi
# SAFEKEYS_ALLOW_INSECURE_KEYSTORE stays set: the old keystore needs it, and
# the runner selects the NEW keystore by explicit backend flags, not by
# falling through to a file.

echo "migrating dev objects: file KEK → $([[ $KEEP_FILE -eq 1 ]] && echo 'new file key' || ([[ "${SAFEKEYS_KEYCHAIN:-0}" == "1" ]] && echo 'macOS Keychain' || echo "OpenBao transit ($SAFEKEYS_VAULT_ADDR)"))"

go run ./scripts/migrate-dev-keys.internal \
  --old-kek "$OLD_KEK_FILE" \
  --dev-dir "$DEV"

# ── Securely delete the old key files ────────────────────────────────────────
secure_delete() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  if command -v srm >/dev/null 2>&1; then
    srm "$f"
  else
    # Overwrite three times, then remove; good enough for the threat model
    # here (an agent with file access, not a forensics lab with an electron
    # microscope).
    local size
    size=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f")
    for _ in 1 2 3; do
      dd if=/dev/urandom of="$f" bs=1 count="$size" conv=notrunc status=none
      sync
    done
    rm -f "$f"
  fi
  echo "deleted $f"
}

secure_delete "$OLD_KEK_FILE"

# The signing key is migrated only when its custody target is NOT a file.
if [[ $KEEP_FILE -eq 0 && -f "$DEV/dev-signing-key" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    # Store the base64 seed as a Keychain item for the control plane.
    seed="$(cat "$DEV/dev-signing-key")"
    security add-generic-password -s safekeys -a dev-signing-key \
      -w "$seed" -U >/dev/null
    echo "signing seed stored in the Keychain (service safekeys, account dev-signing-key)"
    secure_delete "$DEV/dev-signing-key"
  else
    echo "signing seed: on Linux it moves to OpenBao KV (not implemented yet); file kept until then" >&2
  fi
fi

echo
echo "Done. Start the stack with: make dev"