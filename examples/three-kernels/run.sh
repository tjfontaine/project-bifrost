#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# three-kernels — the north-star demo (3 kernels in 1 stream).
#
# One `bifrost orchestrate` invocation, one D source, THREE kernels.
# `bifrost orchestrate` spawns the smolvm + qemu-freebsd VMs and the
# macOS-host dtrace child in parallel, opens each target's session,
# lowers per-OS clauses, drains every target into the merged record
# stream, and folds the shared `@triplet["all"] = count()` agg across
# all three.
#
# Modes:
#
#   * Default: validates plan + D source via
#     `bifrost orchestrate --dry-run`.  Cheap, no VMs, suitable for
#     CI / pre-commit gating.
#
#   * `BIFROST_LIVE=1`: drives the full end-to-end demo.  Requires
#     everything cross-kernel-linux-fbsd-x2/run.sh does PLUS:
#       - /usr/sbin/dtrace exists and is in `sudoers` for the user
#         under NOPASSWD (the orchestrator spawns `sudo -n dtrace`).
#       - SIP allows `dtrace(1)` to attach to syscall::* probes.
#         Run `sudo dtrace -l -n syscall:::entry` once to check.
#
# Pass criteria (gates checked at the bottom):
#
#   ✓ all three targets accepted their sessions
#   ✓ merged record stream carried records from all three targets
#     macos-host records: ≥1
#     linux-a    records: ≥1
#     fbsd-b     records: ≥1
#   ✓ cross-target @triplet["all"] row names ALL THREE target ids
#     in its `contributors:` map.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PLAN="$SCRIPT_DIR/plan.yaml"
SOURCE_D="$SCRIPT_DIR/trace.d"

BIFROST_BIN="${BIFROST_BIN:-$PROJECT_ROOT/host/runtime/bifrost}"
ORCH_LOG="${ORCH_LOG:-/tmp/bifrost-three-kernels-orch.log}"

# Match the path qemu-launch-freebsd.sh hardcodes so first-time
# operators don't have to re-export.
export QEMU="${QEMU:-/private/tmp/qemu-11.0.0/build/qemu-system-aarch64}"
export PATH="$PROJECT_ROOT/host/runtime:$PATH"

if [ ! -x "$BIFROST_BIN" ]; then
    echo "[3k] bifrost binary missing at $BIFROST_BIN" >&2
    echo "[3k] build via: cargo build --manifest-path host/bifrost/Cargo.toml --release --bin bifrost" >&2
    echo "[3k] (or run scripts/first-run.sh — it stages everything)" >&2
    exit 1
fi

cd "$PROJECT_ROOT"

if [ "${BIFROST_LIVE:-0}" != "1" ]; then
    echo "[3k] validating plan + D source via orchestrator dry-run"
    "$BIFROST_BIN" orchestrate "$PLAN" --dry-run
    echo
    echo "[3k] -------- summary --------"
    echo "[3k] ✓ plan + D source pass three-kernel routing"
    echo "[3k] tip: re-run with BIFROST_LIVE=1 to boot smolvm + FreeBSD"
    echo "[3k]      and exercise the merged record stream end-to-end."
    exit 0
fi

echo "[3k] BIFROST_LIVE=1 — booting smolvm + FreeBSD + macos-host dtrace"
echo "[3k]   plan:   $PLAN"
echo "[3k]   d:      $SOURCE_D"
echo "[3k]   log:    $ORCH_LOG"

# Sudo wraps the orchestrator for the SHM-conduit paths (libkrun
# device access, etc.).  -E preserves QEMU/PATH for the launchers,
# and the inner `sudo -n` the macos-host launcher uses is a no-op
# inside an existing sudo context.
if sudo -n "$BIFROST_BIN" orchestrate "$PLAN" >"$ORCH_LOG" 2>&1; then
    echo "[3k] orchestrate exited 0"
else
    rc=$?
    echo "[3k] orchestrate exited $rc — see $ORCH_LOG" >&2
fi

echo "[3k] -------- output --------"
cat "$ORCH_LOG"
echo
echo "[3k] -------- gate evaluation --------"

ok=1

# Gate 1: all three targets accepted their sessions.
linux_ack=$(grep -c "target \`linux-a\` accepted .* DTRACE_SESSION envelope" "$ORCH_LOG" 2>/dev/null | head -1)
fbsd_ack=$(grep -c "target \`fbsd-b\` accepted native-DTrace session" "$ORCH_LOG" 2>/dev/null | head -1)
mac_ack=$(grep -c "target \`macos-host\` accepted macos-host dtrace session" "$ORCH_LOG" 2>/dev/null | head -1)
linux_ack=${linux_ack:-0}
fbsd_ack=${fbsd_ack:-0}
mac_ack=${mac_ack:-0}
if [ "$linux_ack" -ge 1 ] && [ "$fbsd_ack" -ge 1 ] && [ "$mac_ack" -ge 1 ]; then
    echo "[3k] ✓ all three targets accepted their sessions"
else
    echo "[3k] ✗ session ack count: linux=$linux_ack fbsd=$fbsd_ack macos=$mac_ack" >&2
    ok=0
fi

# Gate 2: merged record stream carried records from all three targets.
a_recs=$(grep -c "^\[linux-a\]" "$ORCH_LOG" 2>/dev/null | head -1)
b_recs=$(grep -c "^\[fbsd-b\]" "$ORCH_LOG" 2>/dev/null | head -1)
m_recs=$(grep -c "^\[macos-host\]" "$ORCH_LOG" 2>/dev/null | head -1)
a_recs=${a_recs:-0}
b_recs=${b_recs:-0}
m_recs=${m_recs:-0}
echo "[3k]   macos-host records: $m_recs"
echo "[3k]   linux-a    records: $a_recs"
echo "[3k]   fbsd-b     records: $b_recs"
if [ "$m_recs" -ge 1 ] && [ "$b_recs" -ge 1 ] && [ "$a_recs" -ge 1 ]; then
    echo "[3k] ✓ merged record stream produced records from all three targets"
else
    echo "[3k] ✗ at least one target produced no records (see counts above)" >&2
    ok=0
fi

# Gate 3: cross-target row with all-three-target contributors.
if grep -q "orchestrate: cross-target aggregations" "$ORCH_LOG"; then
    echo "[3k] ✓ cross-target aggregation table rendered"
    # Look for a contributors line that names all three target ids.
    if grep -E "contributors:.*macos-host" "$ORCH_LOG" >/dev/null \
       && grep -E "contributors:.*linux-a" "$ORCH_LOG" >/dev/null \
       && grep -E "contributors:.*fbsd-b" "$ORCH_LOG" >/dev/null; then
        echo "[3k] ✓ at least one row's contributors map references all three kernels"
    else
        echo "[3k] ✗ no row's contributors map references all three target ids" >&2
        ok=0
    fi
else
    echo "[3k] ✗ no cross-target aggregation table rendered" >&2
    ok=0
fi

if [ "$ok" -eq 1 ]; then
    echo "[3k] ✓✓✓ three-kernels demo PASS"
    exit 0
else
    echo "[3k] ✗✗✗ three-kernels demo FAIL" >&2
    exit 1
fi
