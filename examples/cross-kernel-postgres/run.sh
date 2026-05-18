#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# cross-kernel-postgres/run.sh — second cross-kernel demo: proves the
# orchestrator isn't shaped around TCP.  Different probe surface
# (USDT on Linux, fbt on FreeBSD) and a different workload
# (pgbench) reuse the same multi-target plan + merged renderer.
#
# Two modes:
#
#   * Default (BIFROST_LIVE unset): validates the demo's plan + D
#     source via `bifrost orchestrate --dry-run`.  No VM boot.
#
#   * `BIFROST_LIVE=1`: drives `bifrost orchestrate plan.yaml`
#     end-to-end via the orchestrator's launcher module (spawns
#     both VMs, captures conduit-backend pids, drives merged
#     drain).  Requires:
#       - Linux smolvm with the postgres-usdt overlay
#         (see `examples/postgres-usdt/` for the staging path).
#       - FreeBSD overlay with postgres + pgbench (operator-
#         supplied via `FREEBSD_QCOW2_OVERLAY`).

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PLAN="$SCRIPT_DIR/plan.yaml"

BIFROST_BIN="${BIFROST_BIN:-$PROJECT_ROOT/host/runtime/bifrost}"

if [ ! -x "$BIFROST_BIN" ]; then
    echo "[cross-kernel-postgres] bifrost binary missing at $BIFROST_BIN" >&2
    exit 1
fi

cd "$PROJECT_ROOT"

if [ "${BIFROST_LIVE:-0}" = "1" ]; then
    echo "[cross-kernel-postgres] BIFROST_LIVE=1 — running orchestrator end-to-end"
    if [ -z "${FREEBSD_WORKLOAD_DIR:-}" ]; then
        FREEBSD_WORKLOAD_DIR="$PROJECT_ROOT/artifacts/freebsd/workload-postgres"
        export FREEBSD_WORKLOAD_DIR
        "$PROJECT_ROOT/host/runtime/build-freebsd-workload-disk.sh" \
            "$FREEBSD_WORKLOAD_DIR" postgres
    fi
    exec sudo -n -E "$BIFROST_BIN" orchestrate "$PLAN"
fi

echo "[cross-kernel-postgres] validating plan + source via orchestrator dry-run"
"$BIFROST_BIN" orchestrate "$PLAN" --dry-run

echo
echo "[cross-kernel-postgres] -------- summary --------"
echo "[cross-kernel-postgres] ✓ plan + D source pass cross-kernel routing"
echo "[cross-kernel-postgres] ✓ orchestrator lowers Linux LOAD_PROG payloads (step 2)"
echo "[cross-kernel-postgres] ✓ orchestrator spawns both VMs + runs EFI preload via QMP (step 5)"
echo "[cross-kernel-postgres] ✓ cross-target agg reducer + printa renderer wired into session end (step 6)"
echo "[cross-kernel-postgres] tip: re-run with BIFROST_LIVE=1 to fetch + stage the FreeBSD postgresql16+pgbench pkg disk and orchestrate end-to-end"
exit 0
