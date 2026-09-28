#!/usr/bin/env bash
#
# Shared local-development settings.
#
# Sourced by scripts/dev-up.sh, scripts/dev-down.sh, and scripts/demo.sh.
#
# This file exists because the three scripts previously derived the sidecar
# socket path independently: dev-up.sh used the conventional
# $TMPDIR/safekeys/sidecar.sock (so the Go, TypeScript and Python clients all
# discover it with no configuration), while demo.sh and dev-down.sh still
# defaulted to .dev/sidecar.sock. `make demo` then failed to find a sidecar that
# was running, and dev-down left a live socket behind. One definition means the
# scripts cannot drift apart again.
#
# It is sourced, not executed, so it defines variables and functions only.

# shellcheck disable=SC2034  # consumed by the sourcing scripts

# Repository root, derived from this file's location. Works regardless of the
# caller's working directory.
# This file lives in scripts/lib/, so the repo root is TWO levels up from
# here. (dirname of common.sh is scripts/lib; the repo root is its parent's
# parent.) Deriving only one level up made SAFEKEYS_DEV_DIR scripts/.dev — a
# second dev state directory the sidecar used while the CLI and demo scripts
# used .dev/ at the repo root, so `make demo` could not find what the sidecar
# wrote.
SAFEKEYS_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAFEKEYS_ROOT="$(cd "$SAFEKEYS_SCRIPTS_DIR/.." && pwd)"

# Local development state: dev signing key, local KEK, ciphertext folders, logs.
export SAFEKEYS_DEV_DIR="$SAFEKEYS_ROOT/.dev"

# ── The socket path, defined once ────────────────────────────────────────────
# $TMPDIR is not a stable location, and that is deliberate: the Go, TypeScript
# and Python clients all default to <tmp>/safekeys/sidecar.sock, so binding there
# means an agent, the MCP server, and the CLI find the sidecar with no
# environment configuration at all. A caller may still override SAFEKEYS_SOCKET.
safekeys_default_socket() {
  local tmp="${TMPDIR:-/tmp}"
  printf '%s/safekeys/sidecar.sock' "${tmp%/}"
}

export SAFEKEYS_SOCKET="${SAFEKEYS_SOCKET:-$(safekeys_default_socket)}"

# ── Development-only convenience overrides ───────────────────────────────────
# These match the defaults the control plane and sidecar would use anyway; they
# are set explicitly so a developer's ambient environment cannot half-configure
# the stack.
export SAFEKEYS_API_KEY="${SAFEKEYS_API_KEY:-dev-api-key}"
export SAFEKEYS_CONTROL_PLANE_URL="${SAFEKEYS_CONTROL_PLANE_URL:-http://localhost:8080}"
export SAFEKEYS_AUDIENCE="${SAFEKEYS_AUDIENCE:-env-local}"
export SAFEKEYS_PRINCIPAL="${SAFEKEYS_PRINCIPAL:-operator}"
export SAFEKEYS_FOLDER="${SAFEKEYS_FOLDER:-$SAFEKEYS_DEV_DIR/folder}"

# ── Dev KEK custody (safekeys/dev-key-custody) ───────────────────────────────
# The KEK must not sit in a plaintext file the coding agent's OS user can
# read. The default ladder:
#
#   1. SAFEKEYS_VAULT_ADDR is already set → use it (OpenBao/Vault transit).
#   2. macOS → SAFEKEYS_KEYCHAIN=1: the KEK is a Keychain item whose ACL
#      grants the sidecar binary. No plaintext key file exists.
#   3. Otherwise (Linux without a vault) → the containerised dev OpenBao is
#      REQUIRED. dev-up.sh starts it if needed; the sidecar gets transit.
#   4. A plaintext KEK file only ever appears behind an explicit, loud
#      opt-in: SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1.
if [[ -z "${SAFEKEYS_VAULT_ADDR:-}" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    export SAFEKEYS_KEYCHAIN="${SAFEKEYS_KEYCHAIN:-1}"
  fi
fi
export SAFEKEYS_VAULT_ADDR="${SAFEKEYS_VAULT_ADDR:-http://localhost:8200}"
