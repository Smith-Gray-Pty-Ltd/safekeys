#!/usr/bin/env bash
#
# Stop the Safekeys development stack started by dev-up.sh --daemon.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="$ROOT/.dev"

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

# The sidecar removes its own socket on a clean shutdown.
[[ -S "$DEV/sidecar.sock" ]] && rm -f "$DEV/sidecar.sock"

if [[ $stopped -eq 0 ]]; then
  echo "nothing running"
fi
