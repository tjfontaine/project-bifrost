#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run every self-contained demo serially and keep the full logs.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LOG_ROOT="${LOG_ROOT:-/tmp/bifrost-full-demo-sweep-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$LOG_ROOT"

DEMOS=(
    redis-smoke-test
    compile-profile
    cross-domain-http
    failed-opens
    intra-guest-http
    postgres-usdt
    probe-control
    profile-stub
    redis-uprobe
    sched-multi
    scheduler-offcpu
)

printf '[demo-sweep] logs: %s\n' "$LOG_ROOT" | tee "$LOG_ROOT/summary.log"

failures=0
for demo in "${DEMOS[@]}"; do
    printf '\n===== %s =====\n' "$demo" | tee -a "$LOG_ROOT/summary.log"

    sudo -n host/runtime/cleanup.sh >"$LOG_ROOT/${demo}.precleanup.log" 2>&1 || true
    third_party/smolvm/target/release/smolvm machine stop >>"$LOG_ROOT/${demo}.precleanup.log" 2>&1 || true
    # Reset persistent overlay state so demos start with a clean
    # rootfs.  Upstream smolvm reuses a "default" machine's overlay
    # across `machine run -d` invocations even when --name is
    # omitted; without this, overlay layer composition from one
    # demo can collide with the next and surface as EUCLEAN (errno
    # 117) at mount time.
    third_party/smolvm/target/release/smolvm machine delete -f default >>"$LOG_ROOT/${demo}.precleanup.log" 2>&1 || true

    rc=0
    if [ "$demo" = "profile-stub" ]; then
        BIFROST="$ROOT/host/runtime/bifrost" \
            "examples/$demo/run.sh" >"$LOG_ROOT/${demo}.out" 2>"$LOG_ROOT/${demo}.err" || rc=$?
    else
        "examples/$demo/run.sh" >"$LOG_ROOT/${demo}.out" 2>"$LOG_ROOT/${demo}.err" || rc=$?
    fi

    printf '[demo-sweep] %s rc=%s\n' "$demo" "$rc" | tee -a "$LOG_ROOT/summary.log"
    grep -E '\[demo-harness\] (PASS|FAIL)|\[redis-smoke-test\] (records observed|.*cross-domain trace working)|parsed:|dtrace summary|ready banner|OBSERVER_ATTACH|error|Error' \
        "$LOG_ROOT/${demo}.out" "$LOG_ROOT/${demo}.err" 2>/dev/null \
        | tail -80 | tee -a "$LOG_ROOT/summary.log"

    sudo -n host/runtime/cleanup.sh >"$LOG_ROOT/${demo}.postcleanup.log" 2>&1 || true
    third_party/smolvm/target/release/smolvm machine stop >>"$LOG_ROOT/${demo}.postcleanup.log" 2>&1 || true

    if [ "$rc" -ne 0 ]; then
        failures=$((failures + 1))
    fi
done

# Primer sweep: every D-language feature (ERROR fault accounting,
# clear, lquantize, llquantize, normalize/trunc render hints,
# speculate/commit/discard, tracemem action, vtimestamp) exercised end-to-end
# against a live smolvm + redis workload.  Per-primer logs land
# under /tmp/bifrost-primer-sweep-<ts>/.
printf '\n===== primer-sweep =====\n' | tee -a "$LOG_ROOT/summary.log"
prc=0
examples/primers/sweep.sh >"$LOG_ROOT/primer-sweep.out" 2>"$LOG_ROOT/primer-sweep.err" || prc=$?
printf '[demo-sweep] primer-sweep rc=%s\n' "$prc" | tee -a "$LOG_ROOT/summary.log"
grep -E '\[primer-sweep\] (.*PASS|.*FAIL|complete:)' \
    "$LOG_ROOT/primer-sweep.out" "$LOG_ROOT/primer-sweep.err" 2>/dev/null \
    | tail -20 | tee -a "$LOG_ROOT/summary.log"
if [ "$prc" -ne 0 ]; then
    failures=$((failures + 1))
fi

# Cross-kernel dry-run gates: the cross-kernel demos validate plan + D
# routing through `bifrost orchestrate --dry-run`.  These don't
# boot any VMs — they catch regressions in cross-kernel clause
# routing (route_clauses), plan parsing, and orchestrator CLI
# dispatch in CI without the FreeBSD provider-coverage blocker the
# live demos depend on.
printf '\n===== cross-kernel dry-run gates =====\n' | tee -a "$LOG_ROOT/summary.log"
for ck_demo in cross-kernel-tcp cross-kernel-postgres; do
    rc=0
    examples/${ck_demo}/run.sh \
        >"$LOG_ROOT/${ck_demo}.out" \
        2>"$LOG_ROOT/${ck_demo}.err" || rc=$?
    printf '[demo-sweep] %s rc=%s\n' "$ck_demo" "$rc" \
        | tee -a "$LOG_ROOT/summary.log"
    grep -E '\[cross-kernel-.*\] (✓|PASS|FAIL|\[v1 PENDING\])|orchestrate: routed' \
        "$LOG_ROOT/${ck_demo}.out" 2>/dev/null \
        | tail -20 | tee -a "$LOG_ROOT/summary.log"
    if [ "$rc" -ne 0 ]; then
        failures=$((failures + 1))
    fi
done

printf '\n[demo-sweep] complete: failures=%s logs=%s\n' "$failures" "$LOG_ROOT" \
    | tee -a "$LOG_ROOT/summary.log"

if [ "$failures" -ne 0 ]; then
    exit 1
fi
