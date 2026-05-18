#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — failed-open workload.  Boots localhost:5005/bifrost-bench:latest in smolvm
# and drives a guest-internal loop that mixes:
#   - `cat /etc/missing-$RANDOM` (produces ENOENT)
#   - `cat /etc/shadow`  as non-root (produces EACCES)
#   - normal `ls /etc`   (control — succeeds)
#
# This produces a steady stream of negative-retval do_sys_openat2
# returns, so the `fbt:guest:do_sys_openat2:return /retval < 0/`
# clause in probe.d aggregates a meaningful (execname, errno)
# distribution.
#
# Workload is driven by short `smolvm machine exec` bursts after
# the VM is ready.  Long exec calls monopolize the agent socket,
# but short bursts are reliable and exercise the same guest kernel
# open path while the trace is attached.
#
# Knobs (env):
#   IMAGE       base image  (default: localhost:5005/bifrost-bench:latest)
#   FIRE_GAP    seconds between bursts (default: 0.05)

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

echo "[setup] launching $IMAGE — entrypoint idles; setup drives short failed-open bursts"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image "$IMAGE" \
        -- bash -c 'sleep infinity' \
    2>&1 | tail -3

PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
echo "[setup] smolvm pid=$PID"
sleep 2

echo "[setup] starting failed-open exec burst loop"
(
    while :; do
        "$SMOLVM" machine exec -- sh -c '
            useradd -m -u 1000 alice 2>/dev/null || true
            for i in $(seq 1 40); do
                cat /etc/missing-$i-$$ 2>/dev/null || true
                su -s /bin/sh alice -c "cat /etc/shadow 2>/dev/null" || true
                ls /etc >/dev/null 2>&1 || true
            done
        ' >/dev/null 2>&1 || true
        sleep "$FIRE_GAP"
    done
) &
WORKLOAD_PID=$!

cat <<MSG

[setup] ════════════════════════════════════════════════════════════
[setup] ready. smolvm pid=$PID, mixed-failure workload running
[setup]
[setup] in another shell, run bifrost (dtrace-style):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -s examples/failed-opens/probe.d
[setup]
[setup] expect ENOENT (-2) from random-name cats, EACCES (-13)
[setup] from the alice→/etc/shadow attempts.
[setup] ════════════════════════════════════════════════════════════

MSG

echo "[setup] workload running (pid=$WORKLOAD_PID). ^C to tear down."
while :; do
    sleep 60
done
