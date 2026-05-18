#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — multi-tracepoint scheduler workload.  Boots
# ubuntu:24.04 in smolvm and runs stress-ng with a fork+IO+CPU
# mix that produces a steady stream of context switches AND
# wakeups (fork-stress in particular drives both —
# sched_process_fork → sched_wakeup_new → sched_switch).
#
# The probe.d in this directory aggregates against
# sched_switch (preempt vs voluntary split via arg0) and
# sched_wakeup, so the workload needs to exercise both.
#
# Knobs (env):
#   IMAGE          base image (default: ubuntu:24.04)
#   STRESS_CPU     CPU workers (default: 2)
#   STRESS_IO      IO workers  (default: 2)
#   STRESS_FORK    fork workers (default: 1; produces lots of
#                                wakeup/exit churn)

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
SMOLVM_BIN="$SMOLVM_DIR/target/release/smolvm"
SMOLVM="$PROJECT_ROOT/host/runtime/smolvm-launch.sh"
CLEANUP="$PROJECT_ROOT/host/runtime/cleanup.sh"
IMAGE="${IMAGE:-localhost:5005/bifrost-bench:latest}"
STRESS_CPU="${STRESS_CPU:-2}"
STRESS_IO="${STRESS_IO:-2}"
STRESS_FORK="${STRESS_FORK:-1}"

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

echo "[setup] launching $IMAGE on smolvm — stress-ng entrypoint"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image "$IMAGE" \
        -- bash -c "
            set -e
            if ! command -v stress-ng >/dev/null; then
                apt-get update -qq
                apt-get install -y -qq stress-ng >/dev/null 2>&1
            fi
            exec stress-ng \
                --cpu $STRESS_CPU --cpu-method matrixprod \
                --io  $STRESS_IO \
                --fork $STRESS_FORK
        " \
    2>&1 | tail -3

PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
echo "[setup] smolvm pid=$PID — letting stress-ng warm up"
sleep 5

cat <<MSG

[setup] ════════════════════════════════════════════════════════════
[setup] ready. stress-ng running in guest, smolvm pid=$PID
[setup]
[setup] in another shell, run bifrost (dtrace-style):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -s examples/sched-multi/probe.d
[setup]
[setup] this shell will keep stress-ng running until ^C.
[setup] ════════════════════════════════════════════════════════════

MSG

echo "[setup] stress-ng running ($STRESS_CPU cpu / $STRESS_IO io / $STRESS_FORK fork). ^C to tear down."
while :; do
    sleep 60
done
