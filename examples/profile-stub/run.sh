#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# profile-stub demo — renderer validation for the profile-N sample
# channel.
#
# Boots its own smolvm via setup.sh, runs
# `bifrost profile -p $PID --max-samples 1` against it, asserts that
# the CLI synthetic profile sample is rendered with the recognizable
# demo PC, and tears down.
#
# This demo's exit-code / output shape doesn't fit the standard
# `[demo-harness] PASS/FAIL` contract from examples/_common/run-demo.sh
# (no probe.d, no per-fire records, no aggregations) so it owns its
# own VM lifecycle and emits the same `[demo-harness] PASS|FAIL`
# banner the orchestrator regression script greps for.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_NAME="profile-stub"
ROOT="$(cd "$DEMO_DIR/../.." && pwd)"
BIFROST="${BIFROST:-$ROOT/host/runtime/bifrost}"
CLEANUP="$ROOT/host/runtime/cleanup.sh"
SMOLVM="$ROOT/third_party/smolvm/target/release/smolvm"
SETUP="$DEMO_DIR/setup.sh"

if [ ! -x "$BIFROST" ]; then
    echo "[demo-harness] FAIL $DEMO_NAME: bifrost CLI not found at $BIFROST"
    exit 1
fi
if [ ! -x "$SETUP" ]; then
    echo "[demo-harness] FAIL $DEMO_NAME: setup.sh not executable at $SETUP"
    exit 1
fi

LOG_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-demo-${DEMO_NAME}-XXXXXX")
SETUP_LOG="$LOG_ROOT/setup.log"
TRACE_OUT="$LOG_ROOT/profile.out"
SETUP_PID=""

cleanup() {
    if [ -n "${SETUP_PID:-}" ] && kill -0 "$SETUP_PID" 2>/dev/null; then
        kill -TERM "$SETUP_PID" 2>/dev/null || true
    fi
    sudo -n "$CLEANUP" 2>&1 | tail -2 || true
    "$SMOLVM" machine stop 2>&1 | tail -2 || true
    pkill -P $$ 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[demo-harness] starting $DEMO_NAME"
echo "[demo-harness] logs: $LOG_ROOT"

( "$SETUP" </dev/null >"$SETUP_LOG" 2>&1 ) &
SETUP_PID=$!

# Wait for the [setup] ready. banner.
elapsed=0
while [ "$elapsed" -lt 120 ]; do
    if [ -s "$SETUP_LOG" ] && grep -E -q '\[setup\] ready\.' "$SETUP_LOG" 2>/dev/null; then
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done
if ! grep -E -q '\[setup\] ready\.' "$SETUP_LOG" 2>/dev/null; then
    echo "[demo-harness] FAIL $DEMO_NAME: ready banner not seen in 120s"
    tail -n 30 "$SETUP_LOG" >&2 || true
    exit 1
fi

PID=$("$DEMO_DIR/../_common/smolvm-pid.sh" || true)
if [ -z "$PID" ]; then
    echo "[demo-harness] FAIL $DEMO_NAME: smolvm pid not found"
    exit 1
fi
echo "[demo-harness] smolvm pid=$PID; running 'bifrost profile --max-samples 1'"

# bifrost profile attaches to the control SHM and renders one demo
# sample. PID is positional, not `-p $PID` (cf. `bifrost profile
# --help`). Cap with timeout in case the command wedges.
trace_rc=0
timeout 15 "$BIFROST" profile --max-samples 1 "$PID" >"$TRACE_OUT" 2>&1 || trace_rc=$?

# timeout exits 124 on its own deadline; bifrost normally exits 0
# after --max-samples is hit.  Anything else is a hard failure.
case "$trace_rc" in
    0|124) ;;
    *)
        echo "[demo-harness] FAIL $DEMO_NAME: bifrost profile exit=$trace_rc"
        tail -n 20 "$TRACE_OUT" >&2 || true
        exit 1
        ;;
esac

# Assertions:
#   1. The profile command attached to the control SHM.
#   2. At least one sample rendered with a recognizable demo PC.
#      The CLI renders PCs as `{:#018x}` → `0xffffff800dead000` (no
#      underscore); accept either spelling.
if ! grep -q "status  attaching control SHM" "$TRACE_OUT"; then
    echo "[demo-harness] FAIL $DEMO_NAME: profile did not attach control SHM"
    tail -n 20 "$TRACE_OUT" >&2 || true
    exit 1
fi
if ! grep -E -q "0xffffff800dead000|0xffff_ff80_0dea_d000|0dea_d000|0dead000" "$TRACE_OUT"; then
    echo "[demo-harness] FAIL $DEMO_NAME: no demo PC in output"
    tail -n 20 "$TRACE_OUT" >&2 || true
    exit 1
fi

echo "[demo-harness] PASS $DEMO_NAME (samples=1)"
exit 0
