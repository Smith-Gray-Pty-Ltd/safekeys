#!/usr/bin/env bash
#
# Red-team the MCP server: run the known secret-leak attempts through
# resolve_for_tool and prove none of them returns the secret — in raw or
# encoded form, whole or in part.
#
# Covers safekeys/output-control's redteam-script-clean test:
#   - direct dumpers (printenv, env, echo, cat …) — refused by the backstop
#     denylist for CLI-origin resolves and by MCP deny-by-default here
#   - inline-code interpreters (sh -c, python -c, node -e, awk, osascript …)
#   - encodings of the value (base64 folded, hex, percent, JSON-escaped)
#   - partial leaks (cut, prefix/suffix/middle echoes)
#   - write-then-read (the documented limit: relay-only reach)
#   - a control: the command DOES see the value (the test is not vacuous)
#
# Requires a running dev stack (make dev) and a built MCP server
# (cd packages/mcp-server && npm run build).
#
# Usage: ./scripts/redteam-mcp.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "── Red team: probing the Safekeys MCP server ──────────────────────────"
exec node "$ROOT/packages/mcp-server/scripts/mcp-redteam.mjs"