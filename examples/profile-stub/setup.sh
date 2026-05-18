#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — boot a smolvm and idle until ^C.
#
# The VMM is now an opaque conduit and no longer emits synthetic
# profile samples. The CLI's `bifrost profile -p $PID --max-samples 1`
# falls back to a local synthetic sample when no transport sample
# arrives, and the assertions in run.sh confirm the renderer path is
# intact.
#
# Workload is `sleep infinity` — this demo cares about the wire
# path, not about real workload activity, so the cheapest possible
# in-guest occupant suffices.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
SMOLVM_BIN="$SMOLVM_DIR/target/release/smolvm"
SMOLVM="$PROJECT_ROOT/host/runtime/smolvm-launch.sh"
CLEANUP="$PROJECT_ROOT/host/runtime/cleanup.sh"
IMAGE="${IMAGE:-localhost:5005/bifrost-bench:latest}"

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

echo "[setup] launching $IMAGE on smolvm"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image "$IMAGE" \
        -- sh -c 'sleep infinity' \
    2>&1 | tail -3

PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
i=0
while [ -z "$PID" ]; do
    sleep 1
    i=$((i + 1))
    [ "$i" -gt 30 ] && { echo "[setup] timed out waiting for smolvm boot" >&2; exit 1; }
    PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
done

# Profile demo emits on accepted HELLO; the VM just needs to be
# alive and ready to accept the bifrost CLI's attach.  A short
# settle gives libkrun time to finish virtio device init.
sleep 5

cat <<MSG

[setup] ════════════════════════════════════════════════════════════
[setup] ready. smolvm pid=$PID
[setup]   profile CLI will emit a local synthetic sample if needed.
[setup] ════════════════════════════════════════════════════════════

MSG

while :; do sleep 60; done
