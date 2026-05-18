#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run-demo.sh — sourceable bash library exposing `demo_run`.
#
# Each demo's run.sh sets a handful of environment variables (or
# parses its demo.toml) and calls `demo_run "$DEMO_DIR"` to:
#   1. boot smolvm via the demo's own setup.sh (background)
#   2. wait for the "ready" banner
#   3. run host/runtime/bifrost-trace.sh for $RUNTIME_SECONDS
#   4. parse the captured stderr/stdout for:
#        - drops=0           (the libdtrace summary line)
#        - records >= EXPECT_RECORDS (per-fire stdout lines
#          containing `probe_id=`)
#        - agg_rows >= EXPECT_AGG_ROWS (lines following an
#          `  @<name>` header on stderr)
#   5. emit `[demo-harness] PASS|FAIL …` and exit 0/1
#   6. always run cleanup-trap.sh on EXIT, INT, TERM
#
# Inputs (env, set by the demo's run.sh before calling demo_run):
#   DEMO_DIR             absolute path of the demo dir (mandatory)
#   DEMO_NAME            human-readable demo name (defaults to
#                        basename of DEMO_DIR)
#   DEMO_SCRIPT          probe.d-style script under DEMO_DIR
#                        (default: "probe.d")
#   DEMO_SETUP           setup script to run (default: "setup.sh")
#   DEMO_WORKLOAD        "auto" if setup.sh seeds traffic itself,
#                        or "external <cmd>" if the harness must
#                        drive it. (default: "auto")
#   RUNTIME_SECONDS      trace duration (default: 16)
#   EXPECT_RECORDS       minimum per-fire records (default: 1)
#   EXPECT_AGG_ROWS      minimum total agg rows across all
#                        @<name>'s (default: 0)
#   AGG_NAMES            space-separated list of expected
#                        @<name>s (advisory; informational only)
#   READY_PATTERN        regex the harness greps for in the
#                        setup log to know boot is done
#                        (default: "\[setup\] ready\.")
#   READY_TIMEOUT_S      max seconds to wait for the banner
#                        (default: 240)
#
# Outputs:
#   `[demo-harness] PASS <name> (records=N, agg_rows=M)`  → exit 0
#   `[demo-harness] FAIL <name>: <reason>`                → exit 1
#
# Cleanup invariant: EXIT/INT/TERM trap fires `demo_cleanup`,
# defined in cleanup-trap.sh (sourced below).

set -euo pipefail

# Resolve project root from this file's location.  Sourced files
# can use $BASH_SOURCE here.
_THIS_FILE="${BASH_SOURCE[0]}"
BIFROST_PROJECT_ROOT="$(cd "$(dirname "$_THIS_FILE")/../.." && pwd)"
export BIFROST_PROJECT_ROOT

# Shared cleanup helper.
# shellcheck source=cleanup-trap.sh
. "$BIFROST_PROJECT_ROOT/examples/_common/cleanup-trap.sh"

_demo_log() {
    printf '[demo-harness] %s\n' "$*" >&2
}

_demo_fail() {
    _demo_log "FAIL ${DEMO_NAME:-demo}: $*"
    exit 1
}

# Boot the demo's setup.sh in the background and capture its
# combined stdout+stderr to a log file.  Returns the PID via
# stdout so the caller can stash it for cleanup.
_demo_start_setup() {
    local setup_sh="$1"
    local log_file="$2"
    if [ ! -x "$setup_sh" ]; then
        _demo_fail "setup script not executable: $setup_sh"
    fi
    # macOS doesn't ship `setsid`, but the cleanup trap reaps
    # via `pkill -KILL -f "examples/.*setup.sh"` so the whole
    # tree dies even without an explicit pgid.  Discard stdin
    # so any read-from-stdin in setup.sh doesn't block.
    ( "$setup_sh" </dev/null >"$log_file" 2>&1 ) &
    local setup_pid=$!
    echo "$setup_pid"
}

# Block until the ready-banner regex appears in $log_file, or
# RAISE on timeout.  Tail-follows the file so concurrent writers
# don't race us.
_demo_wait_ready() {
    local log_file="$1"
    local pattern="$2"
    local timeout_s="$3"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout_s" ]; do
        if [ -s "$log_file" ] && grep -E -q "$pattern" "$log_file" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    _demo_log "ready banner '$pattern' not seen in ${timeout_s}s"
    _demo_log "tail of setup log:"
    tail -n 40 "$log_file" >&2 || true
    return 1
}

# Locate the smolvm VM pid that the trace will attach to.
_demo_smolvm_pid() {
    "$DEMO_DIR/../_common/smolvm-pid.sh"
}

# Parse the trace log files and emit (records agg_rows drops_ok)
# triple on stdout.  Parses are intentionally simple grep-based
# heuristics; they assume the dtrace_consumer + xagg dump formats
# from host/bifrost/src/dtrace_consumer.rs and cli/xagg.rs.
_demo_parse_trace() {
    local stdout_log="$1"
    local stderr_log="$2"

    # Per-fire records: stdout lines that contain `probe_id=`
    # (every guest-side fire formatted by the libkrun render path
    # carries this token; see control_shmem.rs:129).
    local records
    records=$(grep -c 'probe_id=' "$stdout_log" 2>/dev/null || true)
    [ -z "$records" ] && records=0

    # Aggregation rows on stderr: every `  @<name>` header from
    # cli/xagg.rs is followed by `key value` header + N data
    # rows.  We count rows that look like the table format
    # "<padded key> <number>" — the header itself doesn't match
    # because "value" / "host" / "guest" / "total" aren't digits.
    # Pattern: any line whose final whitespace-separated token is
    # all digits, sitting under an indented agg block.
    local agg_rows
    agg_rows=$(awk '
        /^  @[A-Za-z_][A-Za-z_0-9]*( \(quantize\))?$/ { in_block=1; next }
        /^[[:space:]]*$/ { in_block=0; next }
        in_block && $NF ~ /^[0-9]+$/ {
            # skip header rows: "key value", "key host guest total".
            # The header has $NF == "value" or "total" — handled
            # by the digit check above.  But quantize histograms
            # have lines like "  value          |@@@@..  count" —
            # those DO end in a digit count, which we want.
            n++
        }
        END { print n+0 }
    ' "$stderr_log" 2>/dev/null)
    [ -z "$agg_rows" ] && agg_rows=0

    # drops=0 check: the dtrace summary line lives on stderr
    # (dtrace_consumer.rs:200).  Match the exact `drops=N`
    # token; 0 is a pass, anything else fails.
    local drops_line drops_val drops_ok
    drops_line=$(grep -E '^\[bifrost\] dtrace summary: drops=' "$stderr_log" 2>/dev/null | tail -1 || true)
    if [ -z "$drops_line" ]; then
        # No summary line — trace never ran cleanly.  Treat as
        # NOT-OK, but let the records check produce the better
        # diagnostic if records is also 0.
        drops_ok=0
        drops_val="<no-summary>"
    else
        drops_val=$(printf '%s\n' "$drops_line" | sed -E 's/.*drops=([0-9]+).*/\1/')
        if [ "$drops_val" = "0" ]; then
            drops_ok=1
        else
            drops_ok=0
        fi
    fi

    printf '%s %s %s %s\n' "$records" "$agg_rows" "$drops_ok" "$drops_val"
}

# Main entrypoint.  Demos call this from their run.sh.
demo_run() {
    : "${DEMO_DIR:?demo_run: DEMO_DIR is required}"
    DEMO_NAME="${DEMO_NAME:-$(basename "$DEMO_DIR")}"
    DEMO_SCRIPT="${DEMO_SCRIPT:-probe.d}"
    DEMO_SETUP="${DEMO_SETUP:-setup.sh}"
    DEMO_WORKLOAD="${DEMO_WORKLOAD:-auto}"
    RUNTIME_SECONDS="${RUNTIME_SECONDS:-16}"
    EXPECT_RECORDS="${EXPECT_RECORDS:-1}"
    EXPECT_AGG_ROWS="${EXPECT_AGG_ROWS:-0}"
    AGG_NAMES="${AGG_NAMES:-}"
    READY_PATTERN="${READY_PATTERN:-\[setup\] ready\.}"
    READY_TIMEOUT_S="${READY_TIMEOUT_S:-240}"

    local script_path="$DEMO_DIR/$DEMO_SCRIPT"
    local setup_path="$DEMO_DIR/$DEMO_SETUP"
    [ -f "$script_path" ] || _demo_fail "missing probe script: $script_path"
    [ -f "$setup_path" ] || _demo_fail "missing setup script: $setup_path"

    local log_root
    log_root=$(mktemp -d "${TMPDIR:-/tmp}/bifrost-demo-${DEMO_NAME}-XXXXXX")
    local setup_log="$log_root/setup.log"
    local trace_out="$log_root/trace.out"
    local trace_err="$log_root/trace.err"

    _demo_log "starting $DEMO_NAME (script=$DEMO_SCRIPT, runtime=${RUNTIME_SECONDS}s, expect_records>=$EXPECT_RECORDS, expect_agg_rows>=$EXPECT_AGG_ROWS)"
    _demo_log "logs: $log_root"

    # EXIT/INT/TERM trap installs cleanup BEFORE we boot anything.
    trap 'demo_cleanup' EXIT
    trap 'demo_cleanup; exit 130' INT
    trap 'demo_cleanup; exit 143' TERM

    # 1. Boot smolvm via the demo's setup.sh.
    local setup_pid
    setup_pid=$(_demo_start_setup "$setup_path" "$setup_log")
    _demo_log "setup.sh started (pid=$setup_pid); waiting for '$READY_PATTERN'"

    # 2. Wait for ready banner.
    if ! _demo_wait_ready "$setup_log" "$READY_PATTERN" "$READY_TIMEOUT_S"; then
        _demo_fail "ready banner not observed within ${READY_TIMEOUT_S}s"
    fi

    local smolvm_pid
    smolvm_pid=$(_demo_smolvm_pid)
    if [ -z "$smolvm_pid" ]; then
        _demo_fail "smolvm pid not found"
    fi
    _demo_log "smolvm pid=$smolvm_pid; launching bifrost-trace.sh for ${RUNTIME_SECONDS}s"

    # 3. External workload (if any) goes here, before the trace
    #    starts.  "auto" means setup.sh already drives traffic.
    if [ "$DEMO_WORKLOAD" != "auto" ]; then
        case "$DEMO_WORKLOAD" in
            external\ *)
                local cmd="${DEMO_WORKLOAD#external }"
                _demo_log "starting external workload: $cmd"
                ( eval "$cmd" ) >"$log_root/workload.log" 2>&1 &
                ;;
            *)
                _demo_fail "unrecognized workload mode: '$DEMO_WORKLOAD' (expected 'auto' or 'external <cmd>')"
                ;;
        esac
    fi

    # 4. Run bifrost-trace.sh with a wrapper-side duration
    #    timer.  The wrapper inherits root privilege via sudo so
    #    it CAN signal bifrost directly (which we can't do from
    #    the user-side, since `sudo -n kill` isn't in the
    #    NOPASSWD profile).  --duration-seconds gives the
    #    wrapper a self-imposed deadline that maps to SIGTERM
    #    (with a 5 s grace period before SIGKILL).  bifrost's
    #    TERM handler is the same as its INT handler — flips
    #    the stop flag, flushes aggs, prints drop summary,
    #    exits 143.
    local trace_sh="$BIFROST_PROJECT_ROOT/host/runtime/bifrost-trace.sh"
    local trace_rc=0
    local trace_env_args=()

    if [ -n "${BIFROST_HOST_RESOLVE_UPROBE:-}" ]; then
        trace_env_args+=(--host-resolve-uprobe)
    fi
    if [ -n "${BIFROST_USDT_WORKSPACE_TARGET:-}" ]; then
        trace_env_args+=(--usdt-workspace-target)
    fi
    if [ -n "${BIFROST_ROOTFS:-}" ]; then
        trace_env_args+=(--rootfs="$BIFROST_ROOTFS")
    fi

    if [ "${#trace_env_args[@]}" -gt 0 ]; then
        sudo -n "$trace_sh" -p "$smolvm_pid" -s "$script_path" \
            "${trace_env_args[@]}" \
            --duration-seconds="$RUNTIME_SECONDS" \
            >"$trace_out" 2>"$trace_err" &
    else
        sudo -n "$trace_sh" -p "$smolvm_pid" -s "$script_path" \
            --duration-seconds="$RUNTIME_SECONDS" \
            >"$trace_out" 2>"$trace_err" &
    fi
    local trace_pid=$!
    wait "$trace_pid" || trace_rc=$?
    # SIGTERM-induced exit codes (143) and SIGINT (130) are
    # success: it's how we asked the trace to stop.  Anything
    # else is a real failure.  bifrost-trace.sh translates 143
    # to 0 internally, so this is mostly belt-and-suspenders.
    case "$trace_rc" in
        0|130|143) trace_rc=0 ;;
    esac

    _demo_log "trace exited (rc=$trace_rc); parsing output"

    # 5. Parse + assert.
    local parsed records agg_rows drops_ok drops_val
    parsed=$(_demo_parse_trace "$trace_out" "$trace_err")
    records=$(printf '%s' "$parsed" | awk '{print $1}')
    agg_rows=$(printf '%s' "$parsed" | awk '{print $2}')
    drops_ok=$(printf '%s' "$parsed" | awk '{print $3}')
    drops_val=$(printf '%s' "$parsed" | awk '{print $4}')

    _demo_log "parsed: records=$records, agg_rows=$agg_rows, drops=$drops_val"

    local fail_reason=""
    if [ "$drops_ok" != "1" ]; then
        fail_reason="drops!=0 (saw drops=$drops_val)"
    elif [ "$records" -lt "$EXPECT_RECORDS" ]; then
        fail_reason="records=$records < EXPECT_RECORDS=$EXPECT_RECORDS"
    elif [ "$agg_rows" -lt "$EXPECT_AGG_ROWS" ]; then
        fail_reason="agg_rows=$agg_rows < EXPECT_AGG_ROWS=$EXPECT_AGG_ROWS"
    fi

    if [ -n "$fail_reason" ]; then
        _demo_log "tail of trace.err:"
        tail -n 25 "$trace_err" >&2 || true
        _demo_log "tail of trace.out:"
        tail -n 10 "$trace_out" >&2 || true
        _demo_fail "$fail_reason"
    fi

    _demo_log "PASS $DEMO_NAME (records=$records, agg_rows=$agg_rows)"
    # Trap on EXIT will run cleanup; explicit exit 0 here so we
    # don't fall through to a strict-mode pipeline failure later.
    exit 0
}
