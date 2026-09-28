#!/usr/bin/env bash
#
# Set up the separate-user local mode (safekeys/dev-key-custody,
# separate-user-socket): the sidecar runs as a dedicated OS user, agents stay
# in their own account, and both meet through a shared group that is checked
# at connection time via kernel peer credentials — not only filesystem
# permissions.
#
# This is the local equivalent of the deployment's sidecar-host-isolation
# contract and the mode to use when the stronger boundary matters (e.g. when
# untrusted agents share a workstation).
#
# Usage:
#   sudo ./scripts/separate-user-mode.sh          # provision + print commands
#   sudo ./scripts/separate-user-mode.sh --start  # provision + start sidecar
#
# macOS and Linux are both supported. On Linux the sidecar keeps the KEK in
# OpenBao transit; on macOS it uses the Keychain (ACL granted to the binary).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIDECAR_USER="${SAFEKEYS_SIDECAR_USER:-_safekeys}"
AGENT_GROUP="${SAFEKEYS_AGENT_GROUP:-safekeys-agents}"
SOCKET_DIR="${SAFEKEYS_SOCKET_DIR:-/var/run/safekeys}"

START=0
[[ "${1:-}" == "--start" ]] && START=1

# ── Provision ────────────────────────────────────────────────────────────────
if [[ "$(uname -s)" == "Darwin" ]]; then
  if ! dscl . -read "/Users/$SIDECAR_USER" >/dev/null 2>&1; then
    echo "creating system user $SIDECAR_USER"
    next_uid=$(($(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | tail -1) + 1))
    dscl . -create "/Users/$SIDECAR_USER"
    dscl . -create "/Users/$SIDECAR_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$SIDECAR_USER" UniqueID "$next_uid"
    dscl . -create "/Users/$SIDECAR_USER" PrimaryGroupID 20
    dscl . -create "/Users/$SIDECAR_USER" NFSHomeDirectory /var/empty
  fi
  if ! dscl . -read "/Groups/$AGENT_GROUP" >/dev/null 2>&1; then
    echo "creating group $AGENT_GROUP"
    next_gid=$(($(dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | sort -n | tail -1) + 1))
    dscl . -create "/Groups/$AGENT_GROUP"
    dscl . -create "/Groups/$AGENT_GROUP" PrimaryGroupID "$next_gid"
  fi
  echo "add yourself:  sudo dscl . -append /Groups/$AGENT_GROUP GroupMembership \"$(whoami)\""
else
  if ! id "$SIDECAR_USER" >/dev/null 2>&1; then
    echo "creating system user $SIDECAR_USER"
    useradd --system --shell /usr/sbin/nologin --home /var/empty "$SIDECAR_USER"
  fi
  if ! getent group "$AGENT_GROUP" >/dev/null 2>&1; then
    echo "creating group $AGENT_GROUP"
    groupadd "$AGENT_GROUP"
  fi
  echo "add yourself:  sudo usermod -aG $AGENT_GROUP \"$(whoami)\""
fi

# ── Socket directory ─────────────────────────────────────────────────────────
mkdir -p "$SOCKET_DIR"
chown "$SIDECAR_USER" "$SOCKET_DIR"
chmod 755 "$SOCKET_DIR"

echo
echo "Separate-user mode is provisioned."
echo "The sidecar must be started as $SIDECAR_USER (it owns the socket directory)."
if [[ $START -eq 1 ]]; then
  # The sidecar reads its KEK from the Keychain (macOS, ACL to its own
  # binary) or OpenBao transit; agents in $AGENT_GROUP connect over the
  # socket and are verified by peer credentials.
  case "$(uname -s)" in
    Darwin)
      exec sudo -u "$SIDECAR_USER" "$ROOT/bin/safekeys-sidecar" \
        -socket "$SOCKET_DIR/sidecar.sock" \
        -socket-group "$AGENT_GROUP"
      ;;
    *)
      exec sudo -u "$SIDECAR_USER" env \
        SAFEKEYS_VAULT_ADDR="${SAFEKEYS_VAULT_ADDR:-http://localhost:8200}" \
        SAFEKEYS_VAULT_TOKEN="${SAFEKEYS_VAULT_TOKEN:-}" \
        "$ROOT/bin/safekeys-sidecar" \
        -socket "$SOCKET_DIR/sidecar.sock" \
        -socket-group "$AGENT_GROUP"
      ;;
  esac
fi
echo "Start it with:  sudo -u $SIDECAR_USER $ROOT/bin/safekeys-sidecar \\"
echo "                  -socket $SOCKET_DIR/sidecar.sock -socket-group $AGENT_GROUP"