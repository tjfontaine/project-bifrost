#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — redis smoke test (cross-domain trace, end-to-end).
#
# Demonstrates the full bifrost pipeline:
#   macOS bifrost CLI → SHM → smolvm libkrun → vsock → guest kernel
#   → bifrost driver → eBPF JIT → kprobe at tsi_control_sendrecv_msg
#   → fires on every redis-cli accept poll → SHMEM ringbuf record
#   → libkrun shmem_consumer_thread → CLI auto-injected sink → stdout
#
# What it does:
#   1. Tears down any leftover smolvm machine
#   2. Boots a fresh smolvm running localhost:5005/bifrost-bench:latest
#   3. Compiles probe.d against the running kernel's BTF
#   4. Attaches bifrost CLI to the smolvm libkrun process and ferries
#      the wrapper through SPSC SHM → guest VQ_CTRL → bifrost_worker
#   5. Captures scheduler records produced while the guest workload runs
#
# Calls `sudo -n` on host/runtime/{bifrost,cleanup.sh} — those
# paths are covered by the host/*/* NOPASSWD sudoers entry.  This
# wrapper itself does not require sudo to invoke.
#
# Prerequisites (all should already be in place after a `cargo make
# build` in third_party/smolvm and a `cargo build --release` in
# host/bifrost):
#   - third_party/smolvm/lib/libkrun.dylib (with bifrost virtio device)
#   - third_party/smolvm/lib/libkrunfw.5.dylib (TSI fixes + bifrost
#     driver + autoload-disabled by default)
#   - host/runtime/bifrost (release CLI binary)

set -eu

# VMM switching:
#   VMM=smolvm (default) — run against libkrun via smolvm `machine run -d`.
#   VMM=qemu             — run against qemu-system-* via qemu-launch.sh
#                          with conduit-backend over vhost-user.
#
# The QEMU path additionally requires:
#   QEMU=/path/to/qemu-system-* built with stock vhost-user-test-device
#   QEMU_ROOTFS=/path/to/docker-exported ext4 rootfs (auto-built if absent)
#   conduit-backend on PATH (host/runtime/).
# QEMU does not need Bifrost-specific patches; conduit-backend adapts the
# guest's PFN SHMEM fallback into the host-visible data SHM.
VMM="${VMM:-smolvm}"

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
SMOLVM="$SMOLVM_DIR/target/release/smolvm"
SMOLVM_LAUNCH="$PROJECT_ROOT/host/runtime/smolvm-launch.sh"
BIFROST="$PROJECT_ROOT/host/runtime/bifrost"
CLEANUP="$PROJECT_ROOT/host/runtime/cleanup.sh"
QEMU_ROOTFS_BUILD="$PROJECT_ROOT/scripts/build-qemu-rootfs.sh"
PROBE_D="$PROJECT_ROOT/examples/redis-smoke-test/probe.d"
if [ "$VMM" = "qemu" ]; then
    WRAPPER="${WRAPPER:-/tmp/bifrost-qemu-probe.bfr7}"
    TRACE_LOG="${TRACE_LOG:-/tmp/bifrost-qemu-trace.log}"
    LAUNCH_LOG="${LAUNCH_LOG:-/tmp/bifrost-qemu-launch.log}"
else
    WRAPPER="${WRAPPER:-/tmp/bifrost-smolvm-probe.bfr7}"
    TRACE_LOG="${TRACE_LOG:-/tmp/bifrost-smolvm-trace.log}"
    LAUNCH_LOG="${LAUNCH_LOG:-/tmp/bifrost-smolvm-launch.log}"
fi
TRACE_SECONDS="${TRACE_SECONDS:-8}"

export PATH="$PROJECT_ROOT/host/runtime:$SMOLVM_DIR/target/release:$PATH"

if [ "$VMM" = "qemu" ]; then
    QEMU_LAUNCH="$PROJECT_ROOT/host/runtime/qemu-launch.sh"
    if [ ! -x "$QEMU_LAUNCH" ]; then
        echo "[redis-smoke-test] $QEMU_LAUNCH not found or not executable" >&2
        exit 1
    fi
    if [ ! -x "$QEMU_ROOTFS_BUILD" ]; then
        echo "[redis-smoke-test] $QEMU_ROOTFS_BUILD not found or not executable" >&2
        exit 1
    fi

    QEMU_ROOTFS="${QEMU_ROOTFS:-$PROJECT_ROOT/artifacts/qemu-rootfs/redis-7-alpine.ext4}"
    BACKEND_PID_FILE="${CONDUIT_BACKEND_PID_FILE:-/tmp/bifrost-qemu-backend.pid}"
    QEMU_PID_FILE="${QEMU_PID_FILE:-/tmp/bifrost-qemu.pid}"

    if [ ! -f "$QEMU_ROOTFS" ]; then
        echo "[redis-smoke-test] building QEMU rootfs from Docker image"
        QEMU_ROOTFS="$QEMU_ROOTFS" "$QEMU_ROOTFS_BUILD"
    fi

    echo "[redis-smoke-test] launching QEMU + redis via qemu-launch"
    rm -f "$BACKEND_PID_FILE" "$QEMU_PID_FILE" "$LAUNCH_LOG"
    QEMU_ROOTFS="$QEMU_ROOTFS" \
        CONDUIT_BACKEND_PID_FILE="$BACKEND_PID_FILE" \
        QEMU_PID_FILE="$QEMU_PID_FILE" \
        "$QEMU_LAUNCH" >"$LAUNCH_LOG" 2>&1 &
    LAUNCH_PID=$!

    echo "[redis-smoke-test] waiting for conduit-backend and guest redis"
    i=0
    BACKEND_PID=""
    while [ -z "$BACKEND_PID" ]; do
        sleep 0.25
        if ! kill -0 "$LAUNCH_PID" 2>/dev/null; then
            echo "[redis-smoke-test] qemu-launch exited before backend pid appeared" >&2
            tail -40 "$LAUNCH_LOG" >&2 || true
            exit 1
        fi
        [ -f "$BACKEND_PID_FILE" ] && BACKEND_PID="$(cat "$BACKEND_PID_FILE")"
        i=$((i + 1))
        [ "$i" -gt 80 ] && { echo "timed out waiting for QEMU backend pid" >&2; exit 1; }
    done

    i=0
    while ! grep -q 'Ready to accept connections' "$LAUNCH_LOG" 2>/dev/null; do
        sleep 1
        if ! kill -0 "$LAUNCH_PID" 2>/dev/null; then
            echo "[redis-smoke-test] qemu-launch exited before redis became ready" >&2
            tail -80 "$LAUNCH_LOG" >&2 || true
            exit 1
        fi
        i=$((i + 1))
        [ "$i" -gt 90 ] && { echo "timed out waiting for QEMU redis boot" >&2; tail -80 "$LAUNCH_LOG" >&2 || true; exit 1; }
    done
    echo "[redis-smoke-test] conduit-backend pid=$BACKEND_PID"

    echo "[redis-smoke-test] compiling BFR7 wrapper (kernel-resolved kfunc names)"
    sudo -n "$BIFROST" -s "$PROBE_D" --emit-ebpf "$WRAPPER" 2>&1 | tail -5

    echo "[redis-smoke-test] launching QEMU trace for ${TRACE_SECONDS}s"
    (
        sleep "$TRACE_SECONDS"
        sudo -n "$CLEANUP" 2>&1 | tail -1
    ) &
    sudo -n "$BIFROST" -s "$PROBE_D" -p "$BACKEND_PID" 2>&1 | tee "$TRACE_LOG"

    kill "$LAUNCH_PID" 2>/dev/null || true
    wait "$LAUNCH_PID" 2>/dev/null || true

    echo
    echo "[redis-smoke-test] -------- summary --------"
    RECORDS=$(grep -c 'guest_kernel:sched_switch:entry' "$TRACE_LOG" || true)
    echo "[redis-smoke-test] records observed in CLI output: $RECORDS"
    echo "[redis-smoke-test] full trace log: $TRACE_LOG"
    echo "[redis-smoke-test] launch log: $LAUNCH_LOG"
    echo "[redis-smoke-test] wrapper (BFR7, kfuncs resolved on the guest): $WRAPPER"
    [ "$RECORDS" -gt 0 ] && {
        echo "[redis-smoke-test] ✓ end-to-end cross-domain trace working"
        exit 0
    }
    echo "[redis-smoke-test] ✗ no records observed — investigate $TRACE_LOG and $LAUNCH_LOG"
    exit 1
elif [ "$VMM" != "smolvm" ]; then
    echo "[redis-smoke-test] unknown VMM=$VMM (expected smolvm|qemu)" >&2
    exit 1
fi

export DYLD_LIBRARY_PATH="$SMOLVM_DIR/lib"
export SMOLVM_AGENT_ROOTFS="$SMOLVM_DIR/target/agent-rootfs"

echo "[redis-smoke-test] cleanup leftover bifrost / smolvm processes"
sudo -n "$CLEANUP" 2>&1 | tail -3 || true
"$SMOLVM" machine stop 2>&1 | tail -3 || true
sleep 1

echo "[redis-smoke-test] launching smolvm + redis via smolvm-launch (RUST_LOG=info,bifrost=debug)"
RUST_LOG=info,krun_devices::virtio::bifrost=debug \
    "$SMOLVM_LAUNCH" machine run -d --net \
        --image localhost:5005/bifrost-bench:latest \
        -- redis-server --bind 0.0.0.0 --protected-mode no \
        >"$LAUNCH_LOG" 2>&1 &
LAUNCH_PID=$!

echo "[redis-smoke-test] waiting for smolvm boot process"
i=0
PID=""
while [ -z "$PID" ]; do
    sleep 1
    STATUS=$("$SMOLVM" machine status 2>/dev/null || true)
    PID=$(printf "%s\n" "$STATUS" | sed -n 's/.*PID: \([0-9][0-9]*\).*/\1/p' | head -1)
    if [ -z "$PID" ]; then
        PID=$(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || pgrep -f '_boot-vm.*boot-config' | tail -1 || true)
    fi
    if [ -z "$PID" ] && ! kill -0 "$LAUNCH_PID" 2>/dev/null && [ "$i" -gt 10 ]; then
        echo "[redis-smoke-test] smolvm-launch exited before boot process appeared" >&2
        tail -20 "$LAUNCH_LOG" >&2 || true
        exit 1
    fi
    i=$((i + 1))
    [ "$i" -gt 90 ] && { echo "timed out waiting for smolvm boot process" >&2; exit 1; }
done
sleep 5
echo "[redis-smoke-test] smolvm pid=$PID"

echo "[redis-smoke-test] compiling BFR7 wrapper (kernel-resolved kfunc names)"
sudo -n "$BIFROST" -s "$PROBE_D" --emit-ebpf "$WRAPPER" 2>&1 | tail -5

echo "[redis-smoke-test] launching trace for ${TRACE_SECONDS}s"
(
    sleep "$TRACE_SECONDS"
    sudo -n "$CLEANUP" 2>&1 | tail -1
) &
sudo -n "$BIFROST" -s "$PROBE_D" -p "$PID" 2>&1 | tee "$TRACE_LOG"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$LAUNCH_PID" 2>/dev/null || break
    sleep 0.5
done
kill "$LAUNCH_PID" 2>/dev/null || true
wait "$LAUNCH_PID" 2>/dev/null || true

echo
echo "[redis-smoke-test] -------- summary --------"
RECORDS=$(grep -c 'guest_kernel:sched_switch:entry' "$TRACE_LOG" || true)
echo "[redis-smoke-test] records observed in CLI output: $RECORDS"
echo "[redis-smoke-test] full trace log: $TRACE_LOG"
echo "[redis-smoke-test] launch log: $LAUNCH_LOG"
echo "[redis-smoke-test] wrapper (BFR7, kfuncs resolved on the guest): $WRAPPER"
[ "$RECORDS" -gt 0 ] && {
    echo "[redis-smoke-test] ✓ end-to-end cross-domain trace working"
    exit 0
}
echo "[redis-smoke-test] ✗ no records observed — investigate $TRACE_LOG and"
echo "[redis-smoke-test]   ~/Library/Caches/smolvm/vms/*/agent-startup-error.log"
exit 1
