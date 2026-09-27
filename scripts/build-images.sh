#!/usr/bin/env bash
# Detached image build helper.
#
# Docker BuildKit in this environment is slow enough that a build outlives a
# single shell invocation, so builds are launched by this script and polled via
# their log file. It is a developer convenience, not a deployment artefact.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

target="${1:-all}"
case "$target" in
  control-plane) files=(Dockerfile.control-plane); tags=(safekeys-control-plane:dev) ;;
  sidecar)       files=(Dockerfile.sidecar);       tags=(safekeys-sidecar:dev) ;;
  all)
    files=(Dockerfile.control-plane Dockerfile.sidecar)
    tags=(safekeys-control-plane:dev safekeys-sidecar:dev)
    ;;
  *) echo "usage: $0 [control-plane|sidecar|all]" >&2; exit 2 ;;
esac

for i in "${!files[@]}"; do
  log="/tmp/sk-build-${target}-${i}.log"
  # nohup + background + redirect: survives the parent shell exiting.
  nohup docker build --progress=plain -f "${files[$i]}" -t "${tags[$i]}" . \
    > "$log" 2>&1 &
  echo "launched ${files[$i]} -> ${tags[$i]} (log $log, pid $!)"
done
