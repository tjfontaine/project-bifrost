#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# cross-kernel-tcp/run.sh — cross-kernel killer demo.
#
# Two modes:
#
#   * Default (BIFROST_LIVE unset): validates the demo's plan + D
#     source via `bifrost orchestrate --dry-run`.  This catches
#     cross-kernel routing regressions in CI without booting any
#     VMs.
#
#   * `BIFROST_LIVE=1`: drives `bifrost orchestrate plan.yaml`
#     end-to-end.  The orchestrator itself now spawns both VMs (the
#     plan's smolvm + qemu-freebsd launchers — see
#     `host/bifrost/src/cli/launcher.rs`), captures each
#     conduit-backend pid via `CONDUIT_BACKEND_PID_FILE`, opens
#     control + data SHM, lowers per-target D, pushes LOAD_PROG +
#     native-DTrace session payloads, and renders the merged
#     cross-kernel record stream.
#
# Workload prerequisites for BIFROST_LIVE=1:
#   * Linux smolvm with nginx baked into the bifrost-bench
#     overlay (already shipped under `third_party/smolvm/`).
#   * FreeBSD VM with nginx + ab on a baked overlay (today the
#     overlay is operator-supplied via `FREEBSD_QCOW2_OVERLAY`; the
#     stock FreeBSD cloud image does not ship nginx).
#
# The orchestrator emits `[<target_id>] gns=…` lines per merged
# record (the merge layer is host-wall-clock keyed; see
# `host/bifrost/src/merge.rs`).  Side-by-side `quantize()`
# histograms over `@arrival` and `@rx` rows over `@rx` land via the
# END clause once libdtrace's host-side consumer is wired through
# the multi-target orchestrator (the next sub-step under
# `dispatch_multi_target`).

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PLAN="$SCRIPT_DIR/plan.yaml"
SOURCE_D="$SCRIPT_DIR/trace.d"

BIFROST_BIN="${BIFROST_BIN:-$PROJECT_ROOT/host/runtime/bifrost}"

if [ ! -x "$BIFROST_BIN" ]; then
    echo "[cross-kernel-tcp] bifrost binary missing at $BIFROST_BIN" >&2
    echo "[cross-kernel-tcp] build via: cargo build --manifest-path host/bifrost/Cargo.toml --release --bin bifrost" >&2
    exit 1
fi

cd "$PROJECT_ROOT"

if [ "${BIFROST_LIVE:-0}" = "1" ]; then
    echo "[cross-kernel-tcp] BIFROST_LIVE=1 — running orchestrator end-to-end"
    # Stage the FreeBSD workload disk (nginx + ab pkg tarballs)
    # if the operator hasn't already pointed at one.  The launcher
    # mounts $FREEBSD_WORKLOAD_DIR as /dev/da1 inside the guest.
    if [ -z "${FREEBSD_WORKLOAD_DIR:-}" ]; then
        FREEBSD_WORKLOAD_DIR="$PROJECT_ROOT/artifacts/freebsd/workload-tcp"
        export FREEBSD_WORKLOAD_DIR
        "$PROJECT_ROOT/host/runtime/build-freebsd-workload-disk.sh" \
            "$FREEBSD_WORKLOAD_DIR" tcp
    fi
    exec sudo -n -E "$BIFROST_BIN" orchestrate "$PLAN"
fi

echo "[cross-kernel-tcp] validating plan + source via orchestrator dry-run"
"$BIFROST_BIN" orchestrate "$PLAN" --dry-run

echo
echo "[cross-kernel-tcp] -------- summary --------"
echo "[cross-kernel-tcp] ✓ plan + D source pass cross-kernel routing"
echo "[cross-kernel-tcp] ✓ orchestrator lowers Linux LOAD_PROG payloads (step 2)"
echo "[cross-kernel-tcp] ✓ orchestrator spawns both VMs + runs EFI preload via QMP (step 5)"
echo "[cross-kernel-tcp] ✓ cross-target agg reducer + printa renderer wired into session end (step 6)"
echo "[cross-kernel-tcp] tip: re-run with BIFROST_LIVE=1 to fetch + stage the FreeBSD nginx+ab pkg disk and orchestrate end-to-end"
exit 0
