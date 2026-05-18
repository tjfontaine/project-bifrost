#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — minimal load.  Boots localhost:5005/bifrost-bench:latest in smolvm and
# drives a `while sleep 0.05; do ls /etc; done` loop inside the
# guest.  Each `ls` opens ~30 files in /etc, so the workload
# produces ~600 do_sys_openat2 fires per second — plenty to
# exercise probe-control's exit-after-N-fires logic without
# overwhelming the trace.
#
# Knobs (env):
#   IMAGE       base image  (default: localhost:5005/bifrost-bench:latest)
#   FIRE_GAP    seconds between `ls` invocations (default: 0.05)

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
SMOLVM_BIN="$SMOLVM_DIR/target/release/smolvm"
SMOLVM="$PROJECT_ROOT/host/runtime/smolvm-launch.sh"
CLEANUP="$PROJECT_ROOT/host/runtime/cleanup.sh"
IMAGE="${IMAGE:-localhost:5005/bifrost-bench:latest}"
FIRE_GAP="${FIRE_GAP:-0.05}"

export DYLD_LIBRARY_PATH="$SMOLVM_DIR/lib"
export SMOLVM_AGENT_ROOTFS="$SMOLVM_DIR/target/agent-rootfs"

cleanup() {
    echo
    echo "[setup] tearing down"
    sudo -n "$CLEANUP" 2>&1 | tail -2 || true
    "$SMOLVM" machine stop 2>&1 | tail -2 || true
    pkill -P $$ 2>/dev/null || true
    exit 0
}
trap cleanup INT TERM

echo "[setup] cleanup leftover bifrost / smolvm processes"
sudo -n "$CLEANUP" 2>&1 | tail -2 || true
"$SMOLVM" machine stop 2>&1 | tail -2 || true
sleep 1

echo "[setup] launching $IMAGE on smolvm — entrypoint sleeps; ls loop runs via exec"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image "$IMAGE" \
        -- bash -c 'sleep infinity' \
    2>&1 | tail -3

PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
echo "[setup] smolvm pid=$PID"
sleep 2

cat <<MSG

[setup] ════════════════════════════════════════════════════════════
[setup] ready. smolvm pid=$PID, entrypoint idling
[setup]
[setup] in another shell, run bifrost (dtrace-style):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -s examples/probe-control/probe.d
[setup]
[setup] this shell will keep firing in-guest \`ls /etc\` until ^C.
[setup] ════════════════════════════════════════════════════════════

MSG

echo "[setup] driving in-guest \`ls /etc\` loop (every ${FIRE_GAP}s)"
while :; do
    "$SMOLVM" machine exec -- ls /etc >/dev/null 2>&1 || true
    sleep "$FIRE_GAP"
done
