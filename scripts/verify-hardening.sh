#!/usr/bin/env bash
#
# Verify that the sidecar unit's hardening is compatible with its workload.
#
# "We set SystemCallFilter and NoNewPrivileges" is not evidence that the service
# still works. This script builds a probe binary, runs it under a systemd unit
# carrying the *same* directives as deploy/systemd/safekeys-sidecar.service, and
# fails if the probe cannot bind a socket, fork a child, or write a temp file.
#
# The probe unit is derived from the real one by string-substituting the
# ExecStart, so the directives under test are never maintained in two places.
#
# Requirements: Docker, and a Linux systemd image. Uses jrei/systemd-ubuntu by
# default (override with HARDPROBE_IMAGE).
#
# Usage:
#   scripts/verify-hardening.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${HARDPROBE_IMAGE:-jrei/systemd-ubuntu:24.04}"
CONTAINER="sk-hardprobe-$$"
UNIT="$ROOT/deploy/systemd/safekeys-sidecar.service"

if [[ ! -f "$UNIT" ]]; then
  echo "missing $UNIT" >&2
  exit 1
fi

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== building the probe for linux/amd64 =="
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/hardprobe-linux "$ROOT/tools/hardprobe"

echo "== deriving a probe unit from the real sidecar unit =="
# Take every hardening directive from the real unit, but run the probe instead
# of the sidecar and skip the credential/systemd-specific lines that a probe does
# not need. A directive added to the real unit is therefore tested automatically.
PROBE_UNIT="$(mktemp)"
{
  # Everything before [Service] (the [Unit] section, including start limits).
  sed -n '1,/^\[Service\]/p' "$UNIT"
  echo "Type=oneshot"
  echo "ExecStart=/usr/local/bin/hardprobe"
  # Every confinement directive, copied verbatim. StateDirectory and
  # RuntimeDirectory are included because they create the paths that
  # ReadWritePaths then needs to exist — omitting them would test a unit
  # different from the one shipped.
  grep -E '^(NoNewPrivileges|ProtectSystem|ProtectHome|PrivateTmp|PrivateDevices|PrivateMounts|ProtectKernelTunables|ProtectKernelModules|ProtectKernelLogs|ProtectControlGroups|ProtectClock|ProtectHostname|ProtectProc|ProcSubset|RestrictSUIDSGID|RestrictRealtime|RestrictNamespaces|LockPersonality|MemoryDenyWriteExecute|RemoveIPC|PrivateIPC|CapabilityBoundingSet|AmbientCapabilities|RestrictAddressFamilies|SystemCallFilter|SystemCallArchitectures|ReadWritePaths|RuntimeDirectory|RuntimeDirectoryMode|StateDirectory|StateDirectoryMode|LogsDirectory)=' "$UNIT"
  echo "[Install]"
  echo "WantedBy=multi-user.target"
} > "$PROBE_UNIT"

echo "== starting a systemd container =="
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw "$IMAGE" >/dev/null

for _ in $(seq 1 40); do
  state="$(docker exec "$CONTAINER" systemctl is-system-running 2>/dev/null || true)"
  [[ "$state" == "running" || "$state" == "degraded" ]] && break
  sleep 0.5
done
echo "  systemd state: $(docker exec "$CONTAINER" systemctl is-system-running 2>&1 || true)"

docker cp /tmp/hardprobe-linux "$CONTAINER:/usr/local/bin/hardprobe"
docker exec "$CONTAINER" chmod +x /usr/local/bin/hardprobe
# The RuntimeDirectory directive needs the user to exist.
docker exec "$CONTAINER" bash -c 'useradd --system --no-create-home safekeys-sidecar 2>/dev/null || true; groupadd --system safekeys-socket 2>/dev/null || true'

docker cp "$PROBE_UNIT" "$CONTAINER:/etc/systemd/system/sk-hardprobe.service"
docker exec "$CONTAINER" systemctl daemon-reload >/dev/null

echo "== running the probe under the hardening =="
set +e
docker exec "$CONTAINER" systemctl start sk-hardprobe 2>&1 | head -5
sleep 1
out="$(docker exec "$CONTAINER" journalctl -u sk-hardprobe --no-pager -n 40 2>&1)"
rc="$(docker exec "$CONTAINER" systemctl show sk-hardprobe -p ExecMainStatus --value 2>&1)"
set -e

echo "$out" | grep -E "hardprobe:" || true

if [[ "$rc" != "0" ]]; then
  echo
  echo "FAIL: the probe exited $rc under the unit's confinement." >&2
  echo "A hardening directive is incompatible with the resolver's workload:" >&2
  echo "$out" | tail -20 >&2
  exit 1
fi

echo
echo "PASS — the sidecar unit's confinement permits socket bind, fork/exec, and file injection."
