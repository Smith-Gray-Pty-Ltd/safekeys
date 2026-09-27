#!/usr/bin/env bash
#
# Stop the Safekeys development stack started by dev-up.sh --daemon.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="$ROOT/.dev"

# Shared settings, so the socket cleaned up here is the one dev-up.sh bound.
# shellcheck source=lib/common.sh
source "$ROOT/scripts/lib/common.sh"

stopped=0
for name in control-plane sidecar; do
  pidfile="$DEV/$name.pid"
  if [[ -f "$pidfile" ]]; then
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && echo "stopped $name (pid $pid)"
      stopped=1
    fi
    rm -f "$pidfile"
  fi
done

# The sidecar removes its own socket on a clean shutdown, so this is only a
# safety net for an unclean exit. SAFEKEYS_SOCKET comes from lib/common.sh, so
# it is the same path dev-up.sh bound.
[[ -S "$SAFEKEYS_SOCKET" ]] && rm -f "$SAFEKEYS_SOCKET"

if [[ $stopped -eq 0 ]]; then
  echo "nothing running"
fi
