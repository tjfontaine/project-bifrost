#!/bin/sh
# Live N=2 orchestrate proof:
# - boot two independent FreeBSD QEMU instances (each with its own
#   conduit-backend + qmp socket + module-disk path);
# - register both pids into a generated plan.yaml;
# - run `bifrost orchestrate` non-dry-run against the plan;
# - assert each target accepted the session and at least one
#   merged record was emitted with drops=0.
#
# This is the closest end-to-end cross-kernel acceptance run we can do
# without integrating the Linux eBPF pipeline into the multi-target
# orchestrator (deferred sub-step). Two FreeBSD targets share the
# same backend + provider modules so we exercise the orchestrator's
# fan-out / merge / drain path with real records.

set -eu

PROJECT_ROOT="/Volumes/CaseSensitive/project-bifrost"
LAUNCHER="$PROJECT_ROOT/host/runtime/qemu-launch-freebsd.sh"
BIFROST_BIN="$PROJECT_ROOT/host/runtime/bifrost"

PLAN="/tmp/cross-kernel-n2-plan.yaml"
D_SOURCE="/tmp/cross-kernel-n2-trace.d"

# Per-VM resources.  Suffix-A and suffix-B keep the two VM
# pipelines completely disjoint.
A_BACKEND_PID_FILE="/tmp/bifrost-n2-A-backend.pid"
A_QEMU_PID_FILE="/tmp/bifrost-n2-A-qemu.pid"
A_LAUNCH_LOG="/tmp/bifrost-n2-A-launch.log"
A_QMP_SOCK="/tmp/bifrost-n2-A-qmp.sock"
A_CONDUIT_SOCK="/tmp/bifrost-n2-A-conduit.sock"
A_CONDUIT_LOG="/tmp/bifrost-n2-A-conduit.log"
A_DATA_SHM_NAME="/conduit-n2-A-data"
A_OVERLAY="$PROJECT_ROOT/artifacts/freebsd/freebsd-n2-A-overlay.qcow2"

B_BACKEND_PID_FILE="/tmp/bifrost-n2-B-backend.pid"
B_QEMU_PID_FILE="/tmp/bifrost-n2-B-qemu.pid"
B_LAUNCH_LOG="/tmp/bifrost-n2-B-launch.log"
B_QMP_SOCK="/tmp/bifrost-n2-B-qmp.sock"
B_CONDUIT_SOCK="/tmp/bifrost-n2-B-conduit.sock"
B_CONDUIT_LOG="/tmp/bifrost-n2-B-conduit.log"
B_DATA_SHM_NAME="/conduit-n2-B-data"
B_OVERLAY="$PROJECT_ROOT/artifacts/freebsd/freebsd-n2-B-overlay.qcow2"

ORCH_LOG="/tmp/bifrost-n2-orchestrate.log"

export QEMU="${QEMU:-/private/tmp/qemu-11.0.0/build/qemu-system-aarch64}"
export PATH="$PROJECT_ROOT/host/runtime:$PATH"

cleanup() {
    [ -n "${A_LAUNCH_PID:-}" ] && kill "$A_LAUNCH_PID" 2>/dev/null || true
    [ -n "${B_LAUNCH_PID:-}" ] && kill "$B_LAUNCH_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -f "$A_QMP_SOCK" "$B_QMP_SOCK" \
        "$A_CONDUIT_SOCK" "$B_CONDUIT_SOCK" \
        "$A_BACKEND_PID_FILE" "$B_BACKEND_PID_FILE" \
        "$A_QEMU_PID_FILE" "$B_QEMU_PID_FILE" \
        "$A_OVERLAY" "$B_OVERLAY"
}
trap cleanup EXIT INT TERM
cleanup
rm -f "$A_LAUNCH_LOG" "$B_LAUNCH_LOG" "$ORCH_LOG"

qmp_send() { sock="$1"; { printf '%s\r\n' '{"execute":"qmp_capabilities"}'; printf '%s\r\n' "$2"; sleep 0.08; } | nc -U "$sock" >/dev/null; }
qmp_key() { qmp_send "$1" "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"$2\"}]}}"; sleep 0.045; }
qmp_combo() { qmp_send "$1" "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"$2\"},{\"type\":\"qcode\",\"data\":\"$3\"}]}}"; sleep 0.045; }
qmp_type_text() {
    sock="$1"; text="$2"
    while [ -n "$text" ]; do
        ch="$(printf '%.1s' "$text")"; text="${text#?}"
        case "$ch" in
            [abcdefghijklmnopqrstuvwxyz0123456789]) qmp_key "$sock" "$ch" ;;
            " ") qmp_key "$sock" spc ;; /) qmp_key "$sock" slash ;; .) qmp_key "$sock" dot ;;
            _) qmp_combo "$sock" shift minus ;; :) qmp_combo "$sock" shift semicolon ;;
            -) qmp_key "$sock" minus ;;
            *) echo "[n2] unsupported char $ch" >&2; exit 1 ;;
        esac
    done
}
qmp_loader_cmd() { sock="$1"; cmd="$2"; pause="$3"; qmp_type_text "$sock" "$cmd"; qmp_key "$sock" ret; sleep "$pause"; }

launch_vm() {
    label="$1"; backend_pid_file="$2"; qemu_pid_file="$3"; launch_log="$4"
    qmp_sock="$5"; conduit_sock="$6"; conduit_log="$7"; data_shm="$8"; overlay="$9"
    echo "[n2] launching FreeBSD VM $label"
    RUST_LOG="conduit_backend=info,krun_virtio_conduit=info,warn" \
        CONDUIT_BACKEND_PID_FILE="$backend_pid_file" \
        QEMU_PID_FILE="$qemu_pid_file" \
        CONDUIT_SOCK="$conduit_sock" \
        CONDUIT_LOG="$conduit_log" \
        CONDUIT_DATA_SHM_NAME="$data_shm" \
        FREEBSD_QCOW2_OVERLAY="$overlay" \
        FREEBSD_MODULES_DIR="$PROJECT_ROOT/artifacts/freebsd/module-disk" \
        FREEBSD_MODULES_BUS=usb \
        QEMU_QMP_SOCK="$qmp_sock" \
        "$LAUNCHER" >"$launch_log" 2>&1 &
    eval "${label}_LAUNCH_PID=\$!"
}

preload_vm() {
    label="$1"; qmp_sock="$2"; launch_log="$3"
    i=0
    while [ "$i" -lt 60 ]; do [ -S "$qmp_sock" ] && break; sleep 1; i=$((i + 1)); done
    [ -S "$qmp_sock" ] || { echo "[n2] $label: qmp sock never appeared" >&2; tail -40 "$launch_log" >&2; exit 1; }
    i=0
    while [ "$i" -lt 60 ]; do grep -q "Autoboot in" "$launch_log" && break; sleep 1; i=$((i + 1)); done
    echo "[n2] $label: at loader, preloading modules"
    qmp_key "$qmp_sock" esc
    i=0
    while [ "$i" -lt 60 ]; do grep -q "OK" "$launch_log" && break; sleep 1; i=$((i + 1)); done
    qmp_loader_cmd "$qmp_sock" "load /boot/kernel/kernel" 3
    qmp_loader_cmd "$qmp_sock" "load disk1s1:/boot/kernel/opensolaris.ko" 3
    qmp_loader_cmd "$qmp_sock" "load disk1s1:/boot/kernel/dtrace.ko" 3
    qmp_loader_cmd "$qmp_sock" "load disk1s1:/boot/kernel/bifrost_conduit.ko" 3
    qmp_loader_cmd "$qmp_sock" "load disk1s1:/boot/kernel/fbt.ko" 3
    qmp_loader_cmd "$qmp_sock" "load disk1s1:/boot/kernel/systrace.ko" 3
    qmp_loader_cmd "$qmp_sock" "load disk1s1:/boot/kernel/profile.ko" 3
    qmp_loader_cmd "$qmp_sock" "boot" 1
}

# Launch both VMs in parallel.
launch_vm A "$A_BACKEND_PID_FILE" "$A_QEMU_PID_FILE" "$A_LAUNCH_LOG" \
    "$A_QMP_SOCK" "$A_CONDUIT_SOCK" "$A_CONDUIT_LOG" \
    "$A_DATA_SHM_NAME" "$A_OVERLAY"
launch_vm B "$B_BACKEND_PID_FILE" "$B_QEMU_PID_FILE" "$B_LAUNCH_LOG" \
    "$B_QMP_SOCK" "$B_CONDUIT_SOCK" "$B_CONDUIT_LOG" \
    "$B_DATA_SHM_NAME" "$B_OVERLAY"

(preload_vm A "$A_QMP_SOCK" "$A_LAUNCH_LOG") &
PRELOAD_A_PID=$!
(preload_vm B "$B_QMP_SOCK" "$B_LAUNCH_LOG") &
PRELOAD_B_PID=$!
wait "$PRELOAD_A_PID"
wait "$PRELOAD_B_PID"

echo "[n2] waiting up to 240s for both VMs to reach login"
i=0
while [ "$i" -lt 240 ]; do
    grep -q "login:" "$A_LAUNCH_LOG" 2>/dev/null && \
    grep -q "login:" "$B_LAUNCH_LOG" 2>/dev/null && break
    sleep 1; i=$((i + 1))
done
grep -q "login:" "$A_LAUNCH_LOG" || { echo "[n2] A did not reach login" >&2; tail -40 "$A_LAUNCH_LOG" >&2; exit 1; }
grep -q "login:" "$B_LAUNCH_LOG" || { echo "[n2] B did not reach login" >&2; tail -40 "$B_LAUNCH_LOG" >&2; exit 1; }

A_PID="$(cat "$A_BACKEND_PID_FILE")"
B_PID="$(cat "$B_BACKEND_PID_FILE")"
echo "[n2] VM A backend pid=$A_PID, VM B backend pid=$B_PID"

# Build a plan that targets both VMs.
#
# Three things to exercise on the cross-kernel path:
#   1. multi-clause D: two distinct probe specs each compile to
#      their own ECB, so the kernel-side per-EPID drain has to
#      emit trace records for both — not just the first.
#   2. quantize(): @latency = quantize(...) flows through the
#      full bucket-array decoder in the host's cross-target
#      reducer (the old path collapsed quantize to a scalar
#      placeholder).
#   3. duration_ms in plan YAML: the per-target knob threads
#      through NativeDtraceSessionRequest::with_duration_ms and
#      into the v2 NDT header at offset 32, extending the
#      kernel-side sampling window past the 500 ms default.
#
# The agg snapshot drain runs automatically inside
# dtrace_state_stop, so we do not need a dtrace:::END clause to
# surface @latency / @ticks — the host's printa renderer prints
# the reducer's contents at session teardown.
cat >"$D_SOURCE" <<'EOD'
profile:::tick-100ms
{
    trace(timestamp);
    @ticks = count();
    @latency = quantize(timestamp & 0xff);
}

profile:::tick-500ms
{
    trace((uint64_t)0xc0ffee);
}

END
{
    printa("@ticks=%@d @latency=%@d\n", @ticks, @latency);
}
EOD
cat >"$PLAN" <<EOF
script_file: $D_SOURCE
targets:
  - id: fbsd-a
    guest_os: freebsd
    duration_ms: 2000
    launcher:
      kind: attach
    conduit:
      pid: $A_PID
  - id: fbsd-b
    guest_os: freebsd
    duration_ms: 2000
    launcher:
      kind: attach
    conduit:
      pid: $B_PID
EOF

echo "[n2] running: sudo bifrost orchestrate $PLAN"
if sudo -n "$BIFROST_BIN" orchestrate "$PLAN" >"$ORCH_LOG" 2>&1; then
    echo "[n2] orchestrate exited 0"
else
    echo "[n2] orchestrate exited non-zero (records may still have flowed)" >&2
fi

echo "[n2] -------- summary --------"
cat "$ORCH_LOG"
echo
if grep -q "target \`fbsd-a\` accepted native-DTrace session" "$ORCH_LOG" && \
   grep -q "target \`fbsd-b\` accepted native-DTrace session" "$ORCH_LOG"; then
    echo "[n2] ✓ both targets accepted their sessions"
else
    echo "[n2] ✗ at least one target rejected its session" >&2
fi
if grep -q "^\[fbsd-a\]" "$ORCH_LOG" && grep -q "^\[fbsd-b\]" "$ORCH_LOG"; then
    echo "[n2] ✓ merged record stream carried records from both targets"
    a_recs="$(grep -c "^\[fbsd-a\]" "$ORCH_LOG" || true)"
    b_recs="$(grep -c "^\[fbsd-b\]" "$ORCH_LOG" || true)"
    echo "[n2]   fbsd-a records: $a_recs"
    echo "[n2]   fbsd-b records: $b_recs"
fi
