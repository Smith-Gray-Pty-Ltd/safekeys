#!/usr/bin/env bash
#
# End-to-end demo: create a secret, use it, revoke it — and prove that the
# model-visible output never contains the plaintext.
#
# Requires a running stack (make dev).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="$ROOT/.dev"

export SAFEKEYS_SOCKET="${SAFEKEYS_SOCKET:-$DEV/sidecar.sock}"
export SAFEKEYS_API_KEY="${SAFEKEYS_API_KEY:-dev-api-key}"
export SAFEKEYS_CONTROL_PLANE_URL="${SAFEKEYS_CONTROL_PLANE_URL:-http://localhost:8080}"
export SAFEKEYS_ALLOW_INSECURE_KEYSTORE=1
export SAFEKEYS_KEYSTORE="${SAFEKEYS_KEYSTORE:-$DEV/kek}"
export SAFEKEYS_FOLDER="${SAFEKEYS_FOLDER:-$DEV/folder}"
export SAFEKEYS_AUDIENCE="${SAFEKEYS_AUDIENCE:-env-local}"
export SAFEKEYS_PRINCIPAL="${SAFEKEYS_PRINCIPAL:-operator}"

SFK="$ROOT/bin/safekeys"
SECRET="sk-live-DEMO-$(python3 -c 'import secrets;print(secrets.token_hex(6))')"

if [[ ! -x "$SFK" ]]; then echo "run: make build" >&2; exit 1; fi
if [[ ! -S "$SAFEKEYS_SOCKET" ]]; then echo "no sidecar at $SAFEKEYS_SOCKET — run: make dev" >&2; exit 1; fi

echo "== 1. Create a secret =="
echo "   The value is written to a file the sidecar reads itself; it is never"
echo "   passed as an argument, so it cannot land in shell history or argv."
SRC="$(mktemp -t safekeys-demo)"
printf '%s' "$SECRET" > "$SRC"
chmod 600 "$SRC"

OUT="$("$SFK" create --object "obj_demo_$$" --file "$SRC" --ttl 30m)"
echo "$OUT" | sed 's/^/   /'
TOKEN="$(echo "$OUT" | awk '/^token:/{print $2}')"

echo
echo "== 2. The ciphertext folder contains no plaintext =="
FOLDER="$DEV/folder/obj_demo_$$"
if grep -rq "$SECRET" "$FOLDER" 2>/dev/null; then
  echo "   FAIL: plaintext found in the folder" >&2; exit 1
fi
echo "   ok — $(find "$FOLDER" -type f | wc -l | tr -d ' ') files, no plaintext"

echo
echo "== 3. The value never appeared in the CLI output =="
if echo "$OUT" | grep -q "$SECRET"; then
  echo "   FAIL: create output contained the secret" >&2; exit 1
fi
echo "   ok — only a token and a path were returned"

echo
echo "== 4. Use the secret: the child sees it, we do not =="
"$SFK" exec --token "$TOKEN" --name API_KEY -- /bin/sh -c \
  'echo "   child saw ${#API_KEY} chars (value not printed)"' 
echo "   exit code: $?"

echo
echo "== 5. Revoke, then confirm it is refused =="
JTI="$(echo "$OUT" | awk '/^token:/{print $2}' | python3 -c '
import sys,base64,json
jws=sys.stdin.read().strip().split("#")[1]
p=jws.split(".")[1]; p+="="*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p))["jti"])')"
"$SFK" revoke --jti "$JTI"

sleep 1
if "$SFK" exec --token "$TOKEN" --name API_KEY -- /bin/sh -c 'echo SHOULD-NOT-RUN' 2>/dev/null | grep -q SHOULD-NOT-RUN; then
  echo "   FAIL: a revoked token still resolved" >&2; exit 1
fi
echo "   ok — revoked token refused"

echo
echo "== 6. Audit trail (metadata only) =="
"$SFK" audit 2>/dev/null | head -5 | sed 's/^/   /'

rm -f "$SRC"
echo
echo "PASS — the secret was created, used and revoked without ever being printed."
