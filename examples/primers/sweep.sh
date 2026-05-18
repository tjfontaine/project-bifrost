#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# sweep.sh — Run every primer against a live smolvm and
# check the rendered output for the per-primer signature.
#
# One shared smolvm boot drives all primers; each primer runs for
# `RUNTIME_SECONDS` (default 8) against the same redis container
# (any openat2-generating workload would do; redis is what
# `examples/redis-smoke-test` already exercises).
#
#   examples/primers/sweep.sh
#
# Exit code: 0 if every primer PASSes; 1 if any fail.  Per-primer
# captures land under `/tmp/bifrost-primer-sweep-<timestamp>/`.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$ROOT/third_party/smolvm"
SMOLVM_BIN="$SMOLVM_DIR/target/release/smolvm"
SMOLVM="$ROOT/host/runtime/smolvm-launch.sh"
BIFROST="$ROOT/host/runtime/bifrost"
BIFROST_TRACE="$ROOT/host/runtime/bifrost-trace.sh"
CLEANUP="$ROOT/host/runtime/cleanup.sh"
RUNTIME_SECONDS="${RUNTIME_SECONDS:-8}"

LOG_ROOT="${LOG_ROOT:-/tmp/bifrost-primer-sweep-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$LOG_ROOT"

export DYLD_LIBRARY_PATH="$SMOLVM_DIR/lib"
export SMOLVM_AGENT_ROOTFS="$SMOLVM_DIR/target/agent-rootfs"

printf '[primer-sweep] logs: %s\n' "$LOG_ROOT" | tee "$LOG_ROOT/summary.log"

echo "[primer-sweep] cleanup leftover bifrost / smolvm processes" \
    | tee -a "$LOG_ROOT/summary.log"
sudo -n "$CLEANUP" 2>&1 | tail -3 >>"$LOG_ROOT/summary.log" || true
"$SMOLVM" machine stop 2>&1 | tail -3 >>"$LOG_ROOT/summary.log" || true
sleep 1

echo "[primer-sweep] booting smolvm + redis (RUST_LOG=info)" \
    | tee -a "$LOG_ROOT/summary.log"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image localhost:5005/bifrost-bench:latest \
        -- redis-server --bind 0.0.0.0 --protected-mode no \
        2>&1 | tail -3 | tee -a "$LOG_ROOT/summary.log"

echo "[primer-sweep] waiting for smolvm boot"
i=0
PID=""
while [ -z "$PID" ]; do
    sleep 1
    STATUS=$("$SMOLVM" machine status 2>/dev/null || true)
    PID=$(printf "%s\n" "$STATUS" | sed -n 's/.*PID: \([0-9][0-9]*\).*/\1/p' | head -1)
    if [ -z "$PID" ]; then
        PID=$(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || true)
    fi
    i=$((i + 1))
    [ "$i" -gt 90 ] && {
        echo "[primer-sweep] timed out waiting for smolvm boot" >&2
        exit 1
    }
done
sleep 5
echo "[primer-sweep] smolvm pid=$PID" | tee -a "$LOG_ROOT/summary.log"

# Start an openat2-generating workload in the guest so the
# primers (which target `fbt:guest:do_sys_openat2:entry`) have
# something to fire on.  `find / -xdev -name '*'` in a loop
# walks the rootfs entirely with one openat2 per inode — at
# minimum a few hundred fires/sec on idle hardware.
echo "[primer-sweep] launching openat2 workload generator in guest" \
    | tee -a "$LOG_ROOT/summary.log"
# `find /etc` walks ~200 inodes in ~50 ms; the 0.5 s sleep
# between rounds keeps the openat2 rate at a few hundred per
# second — visible to the primers without overrunning the
# ringbuf consumer.
(
    while true; do
        "$SMOLVM" machine exec -- sh -c \
            'find /etc -xdev >/dev/null 2>&1' \
            >/dev/null 2>&1 || true
        sleep 0.5
    done
) &
WORKLOAD_PID=$!
trap 'kill "$WORKLOAD_PID" 2>/dev/null || true' EXIT

failures=0

# Per-primer expected-marker contract.  Each entry is
# `<primer>|<expected pattern>` where the pattern is searched in
# the rendered stderr/stdout output.  Pattern is plain `grep -E`
# regex; match ≥ 1 line ⇒ PASS.
PRIMERS=(
    "vtimestamp|^  @vt"
    "tracemem|tracemem="
    "clear|^  @switches"
    "lquantize|\\(lquantize\\)"
    "llquantize|\\(llquantize\\)"
    "normalize-trunc|normalize=100"
    "speculate|^guest_kernel:do_sys_openat2:entry"
    # false-positive regression net.  Body's only
    # mention of the needle is inside a printf literal — must
    # render verbatim, no `arg0` substitution.
    "translator-noinject|args\\[0\\]->prev->comm"
    # BTF-driven chain produces records with
    # the resolved task_struct.se.sum_exec_runtime u64 value in
    # the rendered `value=` slot.  Idle (gpid=0) reads as 0; any
    # non-idle task carries a non-zero ns runtime — match
    # `value=0x[1-9a-f]` so the regex passes only when the BTF
    # chain landed inside a real task_struct.
    "translator|sched_switch:entry .* value=0x[1-9a-f]"
)

for entry in "${PRIMERS[@]}"; do
    primer="${entry%%|*}"
    pattern="${entry#*|}"
    log="$LOG_ROOT/${primer}.log"
    printf '\n===== %s =====\n' "$primer" | tee -a "$LOG_ROOT/summary.log"

    # bifrost-trace.sh wraps bifrost with `--duration-seconds=N`
    # which sends SIGTERM after the timer; bifrost's TERM
    # handler flushes aggs + prints the drop summary so the
    # rendered `@<name>` blocks land in the captured log.
    sudo -n "$BIFROST_TRACE" \
        -s "$ROOT/examples/primers/${primer}.d" \
        -p "$PID" \
        --duration-seconds="$RUNTIME_SECONDS" \
        >"$log" 2>&1 || true

    # Brief settle window so the kernel's per-CPU agg-snapshot
    # ring has time to drain before the next primer attaches —
    # otherwise residual backpressure can defer the next agg
    # dump past the 8 s window.
    sleep 2

    if grep -E "$pattern" "$log" >/dev/null 2>&1; then
        printf '[primer-sweep] %s PASS\n' "$primer" \
            | tee -a "$LOG_ROOT/summary.log"
    else
        failures=$((failures + 1))
        printf '[primer-sweep] %s FAIL (no match for /%s/)\n' \
            "$primer" "$pattern" | tee -a "$LOG_ROOT/summary.log"
        echo "  tail of $log:" >>"$LOG_ROOT/summary.log"
        tail -15 "$log" >>"$LOG_ROOT/summary.log"
    fi
done

echo "[primer-sweep] tearing down smolvm" | tee -a "$LOG_ROOT/summary.log"
sudo -n "$CLEANUP" 2>&1 | tail -2 >>"$LOG_ROOT/summary.log" || true
"$SMOLVM" machine stop 2>&1 | tail -2 >>"$LOG_ROOT/summary.log" || true

printf '\n[primer-sweep] complete: failures=%d logs=%s\n' \
    "$failures" "$LOG_ROOT" | tee -a "$LOG_ROOT/summary.log"
[ "$failures" -eq 0 ]
