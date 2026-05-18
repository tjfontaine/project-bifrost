#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — boot ubuntu:24.04 in smolvm and drive a stress-ng load
# that produces a steady stream of guest context switches.  Three
# tunables (CPU stress, IO stress, fork stress) cover the typical
# scheduler shapes; default settings give ~5-10 K context switches
# per second in the guest.
#
# Knobs (env):
#   IMAGE          base image (default: ubuntu:24.04)
#   STRESS_CPU     CPU workers (default: 2)
#   STRESS_IO     IO workers  (default: 2)
#   STRESS_FORK   fork workers (default: 1; produces lots of
#                                exec/exit churn → many switches)

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

echo "[setup] launching $IMAGE on smolvm"
echo "[setup]   entrypoint apt-installs stress-ng if needed, then runs it in foreground"
echo "[setup]   (stress-ng is the entrypoint so its execs are visible to the trace)"
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
[setup]       -s examples/scheduler-offcpu/probe.d
[setup]
[setup] this shell will keep stress-ng running until ^C.
[setup] ════════════════════════════════════════════════════════════

MSG

# Foreground wait — stress-ng runs inside the guest, this side just
# blocks until the user ^Cs (which trips cleanup()).
echo "[setup] stress-ng running ($STRESS_CPU cpu / $STRESS_IO io / $STRESS_FORK fork). ^C to tear down."
while :; do
    sleep 60
done
