#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — boot the shared bifrost-bench image in smolvm and drive
# short in-guest C compile bursts. Does NOT run the trace.
#
# The workload uses short `machine exec` calls after the ready banner,
# matching the other demos that drive post-ready traffic. Each burst
# runs a real `gcc -c`, so `cc1` and `as` stay visible while the
# host-attached trace runs without a long agent-socket hold.
#
# After this script reports "setup ready", open another shell and
# run bifrost yourself, dtrace-style:
#
#     sudo bifrost \
#         -p $(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || pgrep -f '_boot-vm.*boot-config' | tail -1) \
#         -s examples/compile-profile/probe.d
#
# Or with an inline D expression (`bifrost -n '...'`):
#
#     sudo bifrost \
#         -p $(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || pgrep -f '_boot-vm.*boot-config' | tail -1) \
#         -n 'bifrost::do_sys_openat2:entry { @[execname] = count(); }'
#
# When you have enough samples (^C the bifrost CLI to dump
# aggregations), come back here and ^C this script too.
#
# Calls `sudo -n` on host/runtime/cleanup.sh — that path is covered
# by the host/*/* NOPASSWD sudoers entry.  This wrapper itself does
# not require sudo to invoke.
#
# Knobs (env):
#   IMAGE             demo image (default: localhost:5005/bifrost-bench:latest)
#   READY_DELAY       warmup seconds before reporting ready (default: 5)
#   FIRE_GAP          seconds between compile attempts (default: 0.05).
#                     This is a hot workload by design — `gustack()`
#                     on every cc1 openat at compile-loop rate
#                     overruns the data SHM ring under sustained load
#                     and Bifrost reports guest-ring drops in the
#                     trace summary, matching DTrace's
#                     principal-buffer drop behavior on hot probes.
#                     The renderer advances past the producer
#                     wavefront on each lap so fresh records still
#                     surface; the kernel-side `dropped_records`
#                     counter accounts for the loss.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
SMOLVM_BIN="$SMOLVM_DIR/target/release/smolvm"
SMOLVM="$PROJECT_ROOT/host/runtime/smolvm-launch.sh"
CLEANUP="$PROJECT_ROOT/host/runtime/cleanup.sh"
IMAGE="${IMAGE:-localhost:5005/bifrost-bench:latest}"
READY_DELAY="${READY_DELAY:-5}"
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

echo "[setup] launching $IMAGE on smolvm — entrypoint idles; setup drives gcc bursts"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net --image "$IMAGE" \
        -- bash -c 'sleep infinity' \
    2>&1 | tail -3

PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
echo "[setup] smolvm pid=$PID"

echo "[setup] waiting ${READY_DELAY}s for VM warmup"
sleep "$READY_DELAY"

cat <<EOF

[setup] ════════════════════════════════════════════════════════════
[setup] ready. smolvm pid=$PID, compile bursts starting
[setup]
[setup] in another shell, run bifrost (dtrace-style):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -s examples/compile-profile/probe.d
[setup]
[setup] or with an inline D expression (-n, like dtrace):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -n 'bifrost::do_sys_openat2:entry { @[execname] = count(); }'
[setup]
[setup] this shell keeps compiling until you ^C; teardown via the trap.
[setup] ════════════════════════════════════════════════════════════

EOF

echo "[setup] driving in-guest gcc compile loop (every ${FIRE_GAP}s)"
while :; do
    "$SMOLVM" machine exec -- sh -c '
        set -eu
        mkdir -p /workspace/compile-profile
        cd /workspace/compile-profile
        cat > profile.c <<'"'"'SRC'"'"'
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static uint64_t mix(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    return x ^ (x >> 33);
}

int main(void)
{
    volatile uint64_t acc = 0;
    for (uint64_t i = 0; i < 4096; i++) {
        acc += mix(i);
    }
    printf("%llu\n", (unsigned long long)acc);
    return 0;
}
SRC
        gcc -O2 -g -fno-omit-frame-pointer -c profile.c -o profile.o >/tmp/compile-profile.gcc.log 2>&1
        rm -f profile.o
    ' >/dev/null 2>&1 || true
    sleep "$FIRE_GAP"
done
