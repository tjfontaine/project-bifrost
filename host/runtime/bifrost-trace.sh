#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# bifrost-trace.sh — wrapper that sets DYLD_LIBRARY_PATH +
# SMOLVM_AGENT_ROOTFS internally so it's invokable via
# `sudo -n host/runtime/bifrost-trace.sh ...` (sudoers wildcard
# `host/*/*` matches; -E env-preservation is denied so we set them
# inside the wrapper instead).
#
# Forwards all args to bifrost (after stripping wrapper-only
# flags).
#
# Optional harness flags (consumed here, not forwarded):
#   --require-records=N    After bifrost exits, count stdout
#                          lines that contain `probe_id=` and
#                          exit non-zero if fewer than N were
#                          seen.  Stdout/stderr are passed
#                          through unchanged.
#   --duration-seconds=N   Run bifrost for N seconds, then send
#                          it SIGTERM so flush_aggs() and
#                          drop_summary print before exit.  Gives
#                          a final 5s grace period before SIGKILL
#                          if bifrost doesn't shut down cleanly.
#                          Wrapper waits for the child and returns
#                          0 on SIGTERM-induced shutdown so
#                          callers don't conflate "timed out as
#                          requested" with "trace failed".
#   --host-resolve-uprobe  Forward bifrost's explicit
#                          --host-resolve-uprobe flag.
#   --usdt-workspace-target
#                          Forward bifrost's explicit
#                          --usdt-workspace-target flag.
#   --rootfs=PATH          Forward bifrost's explicit --rootfs flag.
#
# These flags are Phase G additions: the demo harness uses them
# so it can call `sudo -n host/runtime/bifrost-trace.sh ...
# --duration-seconds=16 --require-records=100` and trust the
# wrapper to handle the timer + record floor without needing
# extra sudo grants for `kill`.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
BIFROST="$PROJECT_ROOT/host/bifrost/target/release/bifrost"

export DYLD_LIBRARY_PATH="$SMOLVM_DIR/lib"
export SMOLVM_AGENT_ROOTFS="$SMOLVM_DIR/target/agent-rootfs"

# Strip wrapper-only flags from the forwarded arg list.
require_records=0
duration_seconds=0
forward_args=""
for a in "$@"; do
    case "$a" in
        --require-records=*)
            require_records="${a#--require-records=}"
            ;;
        --duration-seconds=*)
            duration_seconds="${a#--duration-seconds=}"
            ;;
        --host-resolve-uprobe)
            forward_args="$forward_args '--host-resolve-uprobe'"
            ;;
        --usdt-workspace-target)
            forward_args="$forward_args '--usdt-workspace-target'"
            ;;
        --rootfs=*)
            esc=$(printf '%s' "$a" | sed "s/'/'\\\\''/g")
            forward_args="$forward_args '$esc'"
            ;;
        *)
            # Quote the arg so embedded spaces survive the eval.
            esc=$(printf '%s' "$a" | sed "s/'/'\\\\''/g")
            forward_args="$forward_args '$esc'"
            ;;
    esac
done

eval set -- $forward_args

if [ "$require_records" = "0" ] && [ "$duration_seconds" = "0" ]; then
    # Fast path: no wrapper-side processing.  exec so the
    # parent's wait sees bifrost's pid.
    exec "$BIFROST" "$@"
fi

# Slow path: tee bifrost's stdout to a temp file (for the
# require-records gate) and run a background timer (for the
# duration-seconds gate).  POSIX-only — no process substitution;
# pipe through a fifo + background tee instead.
tmp_out=""
tmp_err=""
fifo_dir=""
timer_pid=""

cleanup() {
    if [ -n "$timer_pid" ]; then
        kill "$timer_pid" 2>/dev/null || true
        wait "$timer_pid" 2>/dev/null || true
    fi
    [ -n "$tmp_out" ] && rm -f "$tmp_out"
    [ -n "$tmp_err" ] && rm -f "$tmp_err"
    [ -n "$fifo_dir" ] && rm -rf "$fifo_dir"
}
trap cleanup EXIT INT TERM

# Run bifrost in a way that lets us:
#   - capture stdout to tmp_out for record counting
#   - still pass all output through to our own stdout/stderr
#   - signal it after duration_seconds elapse
tmp_out=$(mktemp -t bifrost-trace.XXXXXX)
tmp_err=$(mktemp -t bifrost-trace-err.XXXXXX)
fifo_dir=$(mktemp -d -t bifrost-trace-fifo.XXXXXX)
fifo_out="$fifo_dir/out"
fifo_err="$fifo_dir/err"
mkfifo "$fifo_out" "$fifo_err"

# tee fans bifrost's output to both the parent's terminal AND
# the temp files for post-run inspection.
tee "$tmp_out" < "$fifo_out" &
tee_out_pid=$!
tee "$tmp_err" < "$fifo_err" >&2 &
tee_err_pid=$!

"$BIFROST" "$@" > "$fifo_out" 2> "$fifo_err" &
bifrost_pid=$!

if [ "$duration_seconds" != "0" ]; then
    # Background timer: TERM bifrost after duration; if it
    # doesn't exit within 5 s, KILL it.  Output of this
    # subshell goes nowhere — it's a control timer.
    (
        sleep "$duration_seconds"
        kill -TERM "$bifrost_pid" 2>/dev/null || exit 0
        i=0
        while [ "$i" -lt 50 ]; do
            kill -0 "$bifrost_pid" 2>/dev/null || exit 0
            sleep 0.1
            i=$((i + 1))
        done
        kill -KILL "$bifrost_pid" 2>/dev/null || true
    ) &
    timer_pid=$!
fi

rc=0
wait "$bifrost_pid" || rc=$?
# When the timer-issued TERM lands, bifrost's signal handler
# sets the stop flag; flush_aggs() and drop_summary print on
# the way out, and the process exits with 143 (128+SIGTERM).
# Treat that as success — we asked for the shutdown.
case "$rc" in
    143|130) rc=0 ;;
esac

# Drain the tees so all output reaches both the terminal and
# the temp files before we read tmp_out for counting.
wait "$tee_out_pid" 2>/dev/null || true
wait "$tee_err_pid" 2>/dev/null || true

# Cancel the timer subshell if bifrost exited early on its own.
if [ -n "$timer_pid" ]; then
    kill "$timer_pid" 2>/dev/null || true
    wait "$timer_pid" 2>/dev/null || true
    timer_pid=""
fi

if [ "$require_records" != "0" ]; then
    # `probe_id=` is the canonical per-fire token (see
    # host/bifrost/src/control_shmem.rs:129).
    seen=$(grep -c 'probe_id=' "$tmp_out" 2>/dev/null || echo 0)
    if [ "$seen" -lt "$require_records" ]; then
        echo "[bifrost-trace] FAIL: --require-records=$require_records but saw only $seen records" >&2
        if [ "$rc" -eq 0 ]; then
            rc=1
        fi
    fi
fi

exit "$rc"
