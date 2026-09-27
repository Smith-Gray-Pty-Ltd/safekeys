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
SAFEKEYS_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
export SAFEKEYS_KEYSTORE="${SAFEKEYS_KEYSTORE:-$SAFEKEYS_DEV_DIR/kek}"
export SAFEKEYS_FOLDER="${SAFEKEYS_FOLDER:-$SAFEKEYS_DEV_DIR/folder}"
