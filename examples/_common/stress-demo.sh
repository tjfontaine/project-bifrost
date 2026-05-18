#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# stress-demo.sh — run one demo (or a comma list of demos) N times
# back-to-back and report per-run PASS/FAIL plus an aggregate flake
# rate. Lets us tell apart:
#
#   "X is deterministically broken"   (0/N pass)
#   "X is a flake"                    (some pass, some fail)
#   "X is reliable"                   (N/N pass)
#
# without rerunning the whole sweep N times by hand.
#
# USAGE
#
#   examples/_common/stress-demo.sh <demo>[,<demo2>,...] [iterations]
#
# DEFAULTS
#
#   iterations defaults to 5.
#
# OUTPUT
#
#   For each demo:
#     [stress] <demo>: pass=A fail=B flake_rate=B/N (B/N×100%)
#     [stress] <demo>: failure signatures: <unique tail-line(s)>
#
#   Per-run captures live under
#   /tmp/bifrost-stress-<demo>-<timestamp>/run-<i>.{out,err}
#   so flake signatures can be diffed across runs.
#
# ENVIRONMENT
#
#   COOLDOWN_SEC   seconds to sleep between runs (default 3).
#                  cleanup-trap.sh already wipes VM state but a
#                  cooldown helps when the host is under pressure
#                  and adjacent runs would otherwise race on
#                  shm_open / socket bind.
#
# Pairs with run-full-sweep.sh — that script answers "does the
# whole sweep pass once?"; this script answers "is demo X
# *reliable*?".
#
# Exits 0 only when every iteration of every named demo passes.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <demo>[,<demo2>,...] [iterations]" >&2
    echo "       e.g. $0 redis-uprobe,cross-domain-http 10" >&2
    exit 2
fi

IFS=',' read -r -a DEMOS <<< "$1"
ITERATIONS="${2:-5}"
COOLDOWN_SEC="${COOLDOWN_SEC:-3}"

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [ "$ITERATIONS" -lt 1 ]; then
    echo "iterations must be a positive integer (got: $ITERATIONS)" >&2
    exit 2
fi

CLEANUP="$ROOT/host/runtime/cleanup.sh"
SMOLVM_BIN="$ROOT/third_party/smolvm/target/release/smolvm"

overall_fail=0
for demo in "${DEMOS[@]}"; do
    run_sh="$ROOT/examples/$demo/run.sh"
    if [ ! -x "$run_sh" ]; then
        echo "[stress] no executable run.sh for demo '$demo' at $run_sh" >&2
        overall_fail=$((overall_fail + 1))
        continue
    fi

    log_root="/tmp/bifrost-stress-$demo-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$log_root"
    echo "[stress] $demo: logs $log_root"

    pass=0
    fail=0
    sig_file="$log_root/failure-signatures.txt"
    : > "$sig_file"

    for i in $(seq 1 "$ITERATIONS"); do
        # Best-effort reset between iterations. cleanup-trap.sh in
        # the demo handles the in-iteration teardown; this is the
        # belt-and-braces case where the prior demo left something
        # alive that would interfere with the next boot.
        sudo -n "$CLEANUP" >/dev/null 2>&1 || true
        "$SMOLVM_BIN" machine stop >/dev/null 2>&1 || true
        "$SMOLVM_BIN" machine delete -f default >/dev/null 2>&1 || true

        out="$log_root/run-$i.out"
        err="$log_root/run-$i.err"
        rc=0
        "$run_sh" >"$out" 2>"$err" || rc=$?

        if [ "$rc" -eq 0 ] && grep -qE "\[demo-harness\] PASS|\[redis-smoke-test\] \xe2\x9c\x93|\[demo-harness\] PASS" "$err" "$out" 2>/dev/null; then
            pass=$((pass + 1))
            printf '[stress] %s: run %d/%d  PASS\n' "$demo" "$i" "$ITERATIONS"
        else
            fail=$((fail + 1))
            sig=$(grep -E "\[demo-harness\] FAIL|LOAD_PROG.*timed out|ring full|drops=<no-summary>|Error:" "$err" "$out" 2>/dev/null | head -1)
            sig="${sig:-rc=$rc no-harness-summary}"
            printf '[stress] %s: run %d/%d  FAIL  (%s)\n' "$demo" "$i" "$ITERATIONS" "$sig"
            printf '%s\n' "$sig" >> "$sig_file"
        fi

        if [ "$i" -lt "$ITERATIONS" ]; then
            sleep "$COOLDOWN_SEC"
        fi
    done

    flake_pct=$(( fail * 100 / ITERATIONS ))
    printf '[stress] %s: pass=%d fail=%d flake_rate=%d/%d (%d%%)\n' \
        "$demo" "$pass" "$fail" "$fail" "$ITERATIONS" "$flake_pct"

    if [ "$fail" -gt 0 ]; then
        echo "[stress] $demo: failure signatures (unique):"
        sort -u "$sig_file" | sed 's/^/[stress]   /'
        overall_fail=$((overall_fail + 1))
    fi
done

exit "$overall_fail"
