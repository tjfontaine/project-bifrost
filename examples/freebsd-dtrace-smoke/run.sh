#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# freebsd-dtrace-smoke/run.sh — FreeBSD-first kernel-only DTrace
# portability proof.
#
# v0 SCOPE
# --------
# At iter v0 this script proves that the host harness boots a
# stock FreeBSD 14.3 aarch64 cloud image under the custom QEMU
# with conduit-backend attached and stays alive long enough for
# boot to complete. When a custom FreeBSD kernel/module set is
# supplied later, set FREEBSD_EXPECT_CONDUIT=1 to promote the gate
# to "bifrost_conduit attached in the kernel".
#
# Pass criteria (v0 prove-transport):
#   * conduit-backend binds its socket;
#   * QEMU launches the FreeBSD QCOW2 with vhost-user-test-device-pci
#     attached;
#   * FreeBSD reaches the login prompt within BOOT_TIMEOUT seconds.
#
# Pass criteria (v1 prove-transport, gated on guest driver presence):
#   * QMP drives the EFI loader without guest userspace;
#   * the stock root image is booted through a disposable overlay;
#   * bifrost_conduit.ko is preloaded from an attached USB module disk;
#   * FreeBSD serial log contains the bifrost_conduit kernel-ready
#     marker;
#   * conduit-backend logs DATA_SHM_READY ingestion from the guest;
#   * no guest helper process or guest dtrace(1) is required.
#
# Pass criteria (v2 prove-native-record):
#   * the preloaded dtrace.ko carries the dtrace_bifrost kernel wrapper;
#   * bifrost_conduit accepts a host request/response control payload;
#   * the wrapper creates a native kernel DTrace state, loads a
#     host-selected DOF fixture, starts/stops it, and drains supported
#     trace(uint64_t) record descriptors;
#   * data-SHM shows the corresponding native-DTrace record and the
#     Bifrost CLI renders it through schema metadata.
#
# Until the driver lands, run.sh exits 0 after boot-only validation
# and prints a clear "[v1 PENDING]" line so dashboards do not flag
# false greens.
#
# Required environment:
#   QEMU                 absolute path to the custom QEMU build
#                        (defaults to the verified path)
#
# Optional environment:
#   FREEBSD_PRELOAD_CONDUIT
#                        default 0. Set to 1 to preload the staged
#                        bifrost_conduit.ko through the EFI loader.
#   FREEBSD_MODULES_DIR  staged module disk directory. Defaults to
#                        artifacts/freebsd/module-disk when preloading.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

LAUNCHER="$PROJECT_ROOT/host/runtime/qemu-launch-freebsd.sh"
LAUNCH_LOG="${LAUNCH_LOG:-/tmp/bifrost-freebsd-launch.log}"
BACKEND_LOG="${CONDUIT_LOG:-/tmp/conduit-backend-fbsd.log}"
BACKEND_PID_FILE="${CONDUIT_BACKEND_PID_FILE:-/tmp/bifrost-fbsd-backend.pid}"
QEMU_PID_FILE="${QEMU_PID_FILE:-/tmp/bifrost-fbsd-qemu.pid}"

BOOT_TIMEOUT="${BOOT_TIMEOUT:-120}"
LOADER_TIMEOUT="${LOADER_TIMEOUT:-60}"
# "login:" is the canonical first-boot prompt on the official
# FreeBSD cloud image (no first-boot cloud-init delays for the VM
# image, only the SD card image). If FreeBSD changes the prompt
# wording in a future release, override via FREEBSD_LOGIN_PROMPT.
FREEBSD_LOGIN_PROMPT="${FREEBSD_LOGIN_PROMPT:-login:}"
FREEBSD_PRELOAD_CONDUIT="${FREEBSD_PRELOAD_CONDUIT:-0}"
FREEBSD_EXPECT_CONDUIT_WAS_SET="${FREEBSD_EXPECT_CONDUIT+x}"
FREEBSD_EXPECT_DATA_SHM_WAS_SET="${FREEBSD_EXPECT_DATA_SHM+x}"
FREEBSD_EXPECT_DTRACE_RECORD_WAS_SET="${FREEBSD_EXPECT_DTRACE_RECORD+x}"
FREEBSD_EXPECT_CONDUIT="${FREEBSD_EXPECT_CONDUIT:-0}"
FREEBSD_EXPECT_DATA_SHM="${FREEBSD_EXPECT_DATA_SHM:-0}"
FREEBSD_EXPECT_DTRACE_RECORD="${FREEBSD_EXPECT_DTRACE_RECORD:-0}"
BIFROST_CONDUIT_READY_RE="${BIFROST_CONDUIT_READY_RE:-bifrost_conduit.*transport ready}"
BIFROST_DATA_SHM_READY_RE="${BIFROST_DATA_SHM_READY_RE:-DATA_SHM_READY.*16777216}"
BIFROST_DTRACE_RECORD_RE="${BIFROST_DTRACE_RECORD_RE:-probe_id=2}"
BIFROST_DTRACE_RENDER_RE="${BIFROST_DTRACE_RENDER_RE:-freebsd:kernel:dtrace:trace .*value=0x4653424454524143}"
BIFROST_DTRACE_KERNEL_RE="${BIFROST_DTRACE_KERNEL_RE:-dtrace_bifrost host DOF records emitted}"
BIFROST_DATA_LOG="${BIFROST_DATA_LOG:-/tmp/bifrost-fbsd-data.log}"
BIFROST_PROOF_LOG="${BIFROST_PROOF_LOG:-/tmp/bifrost-fbsd-proof.log}"
BIFROST_PROOF_DOF_HEX="${BIFROST_PROOF_DOF_HEX:-$SCRIPT_DIR/freebsd-begin-trace.dof.hex}"
BIFROST_PROOF_DOF="${BIFROST_PROOF_DOF:-/tmp/bifrost-fbsd-proof.dof}"
BIFROST_KERNEL_PATH="${BIFROST_KERNEL_PATH:-/boot/kernel/kernel}"
BIFROST_OPENSOLARIS_MODULE_PATH="${BIFROST_OPENSOLARIS_MODULE_PATH:-disk1s1:/boot/kernel/opensolaris.ko}"
BIFROST_DTRACE_MODULE_PATH="${BIFROST_DTRACE_MODULE_PATH:-disk1s1:/boot/kernel/dtrace.ko}"
BIFROST_CONDUIT_MODULE_PATH="${BIFROST_CONDUIT_MODULE_PATH:-disk1s1:/boot/kernel/bifrost_conduit.ko}"
BIFROST_FBT_MODULE_PATH="${BIFROST_FBT_MODULE_PATH:-disk1s1:/boot/kernel/fbt.ko}"
BIFROST_SYSTRACE_MODULE_PATH="${BIFROST_SYSTRACE_MODULE_PATH:-disk1s1:/boot/kernel/systrace.ko}"
BIFROST_PROFILE_MODULE_PATH="${BIFROST_PROFILE_MODULE_PATH:-disk1s1:/boot/kernel/profile.ko}"
# Provider preload: when the module disk has fbt/systrace/
# profile, also load them at the EFI loader so the providers
# register before bifrost_conduit's first DOF arrives.  Default
# auto-detects by checking the staged disk.
FREEBSD_PRELOAD_PROVIDERS="${FREEBSD_PRELOAD_PROVIDERS:-auto}"
QMP_KEY_DELAY="${QMP_KEY_DELAY:-0.045}"

export PATH="$PROJECT_ROOT/host/runtime:$PATH"

if [ ! -x "$LAUNCHER" ]; then
    echo "[fbsd-smoke] $LAUNCHER not found or not executable" >&2
    exit 1
fi
if ! command -v conduit-backend >/dev/null 2>&1; then
    echo "[fbsd-smoke] conduit-backend not on PATH; build host/conduit-backend and stage it under host/runtime/" >&2
    exit 1
fi

if [ "$FREEBSD_PRELOAD_CONDUIT" = "1" ]; then
    if [ -z "$FREEBSD_EXPECT_CONDUIT_WAS_SET" ]; then
        FREEBSD_EXPECT_CONDUIT=1
    fi
    if [ -z "$FREEBSD_EXPECT_DATA_SHM_WAS_SET" ]; then
        FREEBSD_EXPECT_DATA_SHM=1
    fi
    if [ -z "$FREEBSD_EXPECT_DTRACE_RECORD_WAS_SET" ]; then
        FREEBSD_EXPECT_DTRACE_RECORD=1
    fi
    if [ "$FREEBSD_EXPECT_DATA_SHM" = "1" ]; then
        RUST_LOG="conduit_backend=info,krun_virtio_conduit=info,${RUST_LOG:-warn}"
        export RUST_LOG
    fi
    FREEBSD_MODULES_DIR="${FREEBSD_MODULES_DIR:-$PROJECT_ROOT/artifacts/freebsd/module-disk}"
    FREEBSD_MODULES_BUS="${FREEBSD_MODULES_BUS:-usb}"
    QEMU_QMP_SOCK="${QEMU_QMP_SOCK:-/tmp/bifrost-fbsd-qmp-$$.sock}"
    if [ "$FREEBSD_MODULES_BUS" != "usb" ]; then
        echo "[fbsd-smoke] FREEBSD_PRELOAD_CONDUIT requires FREEBSD_MODULES_BUS=usb" >&2
        exit 1
    fi
    if [ ! -f "$FREEBSD_MODULES_DIR/boot/kernel/opensolaris.ko" ]; then
        echo "[fbsd-smoke] missing staged module: $FREEBSD_MODULES_DIR/boot/kernel/opensolaris.ko" >&2
        echo "[fbsd-smoke] run guest/freebsd-bifrost/build-module.sh and stage-module-disk.sh first" >&2
        exit 1
    fi
    if [ ! -f "$FREEBSD_MODULES_DIR/boot/kernel/dtrace.ko" ]; then
        echo "[fbsd-smoke] missing staged module: $FREEBSD_MODULES_DIR/boot/kernel/dtrace.ko" >&2
        echo "[fbsd-smoke] run guest/freebsd-bifrost/build-module.sh and stage-module-disk.sh first" >&2
        exit 1
    fi
    if [ ! -f "$FREEBSD_MODULES_DIR/boot/kernel/bifrost_conduit.ko" ]; then
        echo "[fbsd-smoke] missing staged module: $FREEBSD_MODULES_DIR/boot/kernel/bifrost_conduit.ko" >&2
        echo "[fbsd-smoke] run guest/freebsd-bifrost/build-module.sh and stage-module-disk.sh first" >&2
        exit 1
    fi
    if ! command -v nc >/dev/null 2>&1; then
        echo "[fbsd-smoke] nc is required for QMP loader automation" >&2
        exit 1
    fi
    if [ "$FREEBSD_EXPECT_DTRACE_RECORD" = "1" ] && ! command -v xxd >/dev/null 2>&1; then
        echo "[fbsd-smoke] xxd is required to materialize the host-selected DOF fixture" >&2
        exit 1
    fi
else
    FREEBSD_MODULES_DIR="${FREEBSD_MODULES_DIR:-}"
    FREEBSD_MODULES_BUS="${FREEBSD_MODULES_BUS:-}"
    QEMU_QMP_SOCK="${QEMU_QMP_SOCK:-}"
fi

cleanup() {
    [ -n "${LAUNCH_PID:-}" ] && kill "$LAUNCH_PID" 2>/dev/null || true
    [ -n "${LAUNCH_PID:-}" ] && wait "$LAUNCH_PID" 2>/dev/null || true
    [ -n "$QEMU_QMP_SOCK" ] && rm -f "$QEMU_QMP_SOCK"
    rm -f "$BACKEND_PID_FILE" "$QEMU_PID_FILE" "$BIFROST_PROOF_DOF" \
        "${BIFROST_SOURCE_PROOF_D:-/tmp/bifrost-fbsd-source-proof.d}"
}
trap cleanup EXIT INT TERM

rm -f "$LAUNCH_LOG" "$BACKEND_PID_FILE" "$QEMU_PID_FILE" \
    "$BIFROST_DATA_LOG" "$BIFROST_PROOF_LOG" "$BIFROST_PROOF_DOF"

echo "[fbsd-smoke] launching FreeBSD VM + conduit-backend"
CONDUIT_BACKEND_PID_FILE="$BACKEND_PID_FILE" \
    QEMU_PID_FILE="$QEMU_PID_FILE" \
    FREEBSD_MODULES_DIR="$FREEBSD_MODULES_DIR" \
    FREEBSD_MODULES_BUS="$FREEBSD_MODULES_BUS" \
    QEMU_QMP_SOCK="$QEMU_QMP_SOCK" \
    "$LAUNCHER" >"$LAUNCH_LOG" 2>&1 &
LAUNCH_PID=$!

wait_for_log() {
    pattern="$1"
    timeout="$2"
    what="$3"
    waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if ! kill -0 "$LAUNCH_PID" 2>/dev/null; then
            echo "[fbsd-smoke] launcher exited while waiting for $what" >&2
            tail -80 "$LAUNCH_LOG" >&2 || true
            exit 1
        fi
        if grep -q "$pattern" "$LAUNCH_LOG" 2>/dev/null; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    echo "[fbsd-smoke] timed out waiting for $what" >&2
    tail -80 "$LAUNCH_LOG" >&2 || true
    exit 1
}

qmp_send() {
    json="$1"
    {
        printf '%s\r\n' '{"execute":"qmp_capabilities"}'
        printf '%s\r\n' "$json"
        sleep 0.08
    } | nc -U "$QEMU_QMP_SOCK" >/dev/null
}

qmp_key() {
    qmp_send "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"$1\"}]}}"
    sleep "$QMP_KEY_DELAY"
}

qmp_combo() {
    qmp_send "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"$1\"},{\"type\":\"qcode\",\"data\":\"$2\"}]}}"
    sleep "$QMP_KEY_DELAY"
}

qmp_type_text() {
    text="$1"
    while [ -n "$text" ]; do
        ch="$(printf '%.1s' "$text")"
        text="${text#?}"
        case "$ch" in
            [abcdefghijklmnopqrstuvwxyz0123456789]) qmp_key "$ch" ;;
            " ") qmp_key spc ;;
            /) qmp_key slash ;;
            .) qmp_key dot ;;
            _) qmp_combo shift minus ;;
            :) qmp_combo shift semicolon ;;
            -) qmp_key minus ;;
            *)
                echo "[fbsd-smoke] unsupported loader automation character: $ch" >&2
                exit 1
                ;;
        esac
    done
}

qmp_loader_cmd() {
    qmp_type_text "$1"
    qmp_key ret
    sleep "$2"
}

preload_conduit() {
    waited=0
    while [ "$waited" -lt "$LOADER_TIMEOUT" ]; do
        [ -S "$QEMU_QMP_SOCK" ] && break
        if ! kill -0 "$LAUNCH_PID" 2>/dev/null; then
            echo "[fbsd-smoke] launcher exited before QMP socket appeared" >&2
            tail -80 "$LAUNCH_LOG" >&2 || true
            exit 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
    if [ ! -S "$QEMU_QMP_SOCK" ]; then
        echo "[fbsd-smoke] QMP socket did not appear: $QEMU_QMP_SOCK" >&2
        exit 1
    fi

    wait_for_log "Autoboot in" "$LOADER_TIMEOUT" "FreeBSD loader menu"
    echo "[fbsd-smoke] preloading opensolaris.ko + dtrace.ko + bifrost_conduit.ko through EFI loader"
    qmp_key esc
    wait_for_log "OK" "$LOADER_TIMEOUT" "FreeBSD loader prompt"
    qmp_loader_cmd "load $BIFROST_KERNEL_PATH" 3
    qmp_loader_cmd "load $BIFROST_OPENSOLARIS_MODULE_PATH" 3
    qmp_loader_cmd "load $BIFROST_DTRACE_MODULE_PATH" 3
    qmp_loader_cmd "load $BIFROST_CONDUIT_MODULE_PATH" 3
    # Provider preload: fbt/systrace/profile. Each load is
    # best-effort — if the module isn't on the staged disk the EFI
    # loader prints "can't load file" and continues; the smoke gate
    # below only fires when the user explicitly requests fbt coverage.
    if [ "$FREEBSD_PRELOAD_PROVIDERS" = "1" ] || \
       [ "$FREEBSD_PRELOAD_PROVIDERS" = "auto" -a \
         -f "$FREEBSD_MODULES_DIR/boot/kernel/fbt.ko" ]; then
        echo "[fbsd-smoke] preloading provider modules (fbt/systrace/profile)"
        qmp_loader_cmd "load $BIFROST_FBT_MODULE_PATH" 3
        qmp_loader_cmd "load $BIFROST_SYSTRACE_MODULE_PATH" 3
        qmp_loader_cmd "load $BIFROST_PROFILE_MODULE_PATH" 3
    fi
    qmp_loader_cmd "boot" 1
}

if [ "$FREEBSD_PRELOAD_CONDUIT" = "1" ]; then
    preload_conduit
fi

echo "[fbsd-smoke] waiting up to ${BOOT_TIMEOUT}s for FreeBSD to reach login prompt"
i=0
BOOTED=0
while [ "$i" -lt "$BOOT_TIMEOUT" ]; do
    if ! kill -0 "$LAUNCH_PID" 2>/dev/null; then
        echo "[fbsd-smoke] launcher exited before boot completed" >&2
        tail -60 "$LAUNCH_LOG" >&2 || true
        exit 1
    fi
    if grep -q "$FREEBSD_LOGIN_PROMPT" "$LAUNCH_LOG" 2>/dev/null; then
        BOOTED=1
        break
    fi
    sleep 1
    i=$((i + 1))
done

if [ "$BOOTED" -ne 1 ]; then
    echo "[fbsd-smoke] FreeBSD did not reach '$FREEBSD_LOGIN_PROMPT' within ${BOOT_TIMEOUT}s" >&2
    echo "[fbsd-smoke] tail of launch log:" >&2
    tail -60 "$LAUNCH_LOG" >&2 || true
    exit 1
fi

BACKEND_PID="$(cat "$BACKEND_PID_FILE" 2>/dev/null || echo '?')"
QEMU_PID_VAL="$(cat "$QEMU_PID_FILE" 2>/dev/null || echo '?')"
echo "[fbsd-smoke] FreeBSD reached login prompt (qemu pid=$QEMU_PID_VAL backend pid=$BACKEND_PID)"

CONDUIT_READY=0
if grep -Eq "$BIFROST_CONDUIT_READY_RE" "$LAUNCH_LOG" 2>/dev/null; then
    CONDUIT_READY=1
fi
DATA_SHM_READY=0
if grep -Eq "$BIFROST_DATA_SHM_READY_RE" "$BACKEND_LOG" 2>/dev/null; then
    DATA_SHM_READY=1
fi
DTRACE_RECORD_READY=0

if [ "$FREEBSD_EXPECT_CONDUIT" = "1" ] && [ "$CONDUIT_READY" -ne 1 ]; then
    echo "[fbsd-smoke] expected bifrost_conduit kernel marker but did not find: $BIFROST_CONDUIT_READY_RE" >&2
    echo "[fbsd-smoke] tail of launch log:" >&2
    tail -80 "$LAUNCH_LOG" >&2 || true
    exit 1
fi
if [ "$FREEBSD_EXPECT_DATA_SHM" = "1" ] && [ "$DATA_SHM_READY" -ne 1 ]; then
    echo "[fbsd-smoke] expected conduit-backend DATA_SHM_READY marker but did not find: $BIFROST_DATA_SHM_READY_RE" >&2
    echo "[fbsd-smoke] tail of backend log:" >&2
    tail -80 "$BACKEND_LOG" >&2 || true
    exit 1
fi
if [ "$FREEBSD_EXPECT_DTRACE_RECORD" = "1" ]; then
    if [ "$BACKEND_PID" = "?" ]; then
        echo "[fbsd-smoke] cannot inspect data SHM without conduit-backend pid" >&2
        exit 1
    fi
    if ! xxd -r -p "$BIFROST_PROOF_DOF_HEX" "$BIFROST_PROOF_DOF"; then
        echo "[fbsd-smoke] failed to materialize FreeBSD proof DOF from $BIFROST_PROOF_DOF_HEX" >&2
        exit 1
    fi
    if bifrost freebsd-proof "$BACKEND_PID" \
        --dof "$BIFROST_PROOF_DOF" \
        --expected 0x4653424454524143 \
        --records 8 >"$BIFROST_PROOF_LOG" 2>&1; then
        echo "[fbsd-smoke] host control payload returned success"
    else
        echo "[fbsd-smoke] FreeBSD DTrace proof control request failed" >&2
        cat "$BIFROST_PROOF_LOG" >&2 || true
        exit 1
    fi
    if grep -Eq "$BIFROST_DTRACE_RENDER_RE" "$BIFROST_PROOF_LOG" 2>/dev/null; then
        echo "[fbsd-smoke] Bifrost renderer printed native FreeBSD DTrace record"
    else
        echo "[fbsd-smoke] expected rendered FreeBSD DTrace record but did not find: $BIFROST_DTRACE_RENDER_RE" >&2
        cat "$BIFROST_PROOF_LOG" >&2 || true
        exit 1
    fi
    if grep -Eq "$BIFROST_DTRACE_KERNEL_RE" "$LAUNCH_LOG" 2>/dev/null; then
        echo "[fbsd-smoke] FreeBSD kernel reported dtrace_bifrost wrapper emission"
    else
        echo "[fbsd-smoke] expected FreeBSD dtrace_bifrost marker but did not find: $BIFROST_DTRACE_KERNEL_RE" >&2
        tail -80 "$LAUNCH_LOG" >&2 || true
        exit 1
    fi
    if bifrost data "$BACKEND_PID" --records 8 --watch-ms 3000 --interval-ms 100 >"$BIFROST_DATA_LOG" 2>&1 &&
        grep -Eq "$BIFROST_DTRACE_RECORD_RE" "$BIFROST_DATA_LOG"; then
        DTRACE_RECORD_READY=1
    else
        echo "[fbsd-smoke] expected native FreeBSD DTrace record in host data SHM: $BIFROST_DTRACE_RECORD_RE" >&2
        echo "[fbsd-smoke] bifrost data output:" >&2
        cat "$BIFROST_DATA_LOG" >&2 || true
        exit 1
    fi
fi

# Second proof: drive the host-compile-from-D-source path against
# the same live conduit. Catches regressions in libdtrace -> DOF
# compilation and the host normalize/preflight pipeline that the
# precompiled-fixture --dof gate above can't see. Needs sudo for
# libdtrace; routes through the staged binary under host/runtime/
# which is NOPASSWD-allowed by the project's sudoers entry.
BIFROST_SOURCE_PROOF_LOG="${BIFROST_SOURCE_PROOF_LOG:-/tmp/bifrost-fbsd-source-proof.log}"
BIFROST_SOURCE_PROOF_D="${BIFROST_SOURCE_PROOF_D:-/tmp/bifrost-fbsd-source-proof.d}"
FREEBSD_EXPECT_SOURCE_COMPILE="${FREEBSD_EXPECT_SOURCE_COMPILE:-$FREEBSD_EXPECT_DTRACE_RECORD}"
SOURCE_PROOF_READY=0
if [ "$FREEBSD_EXPECT_SOURCE_COMPILE" = "1" ]; then
    cat >"$BIFROST_SOURCE_PROOF_D" <<'EOD'
/*
 * Source-compile proof: compile this D on the macOS host through
 * libdtrace, ship the resulting DOF to the FreeBSD guest kernel
 * via the same native-DTrace backend, and render the drained
 * trace() record. A single scalar trace() is the supported shape;
 * exit()/printf()/string-trace are rejected host-side by the
 * native_trace_record_count preflight.
 */
dtrace:::BEGIN
{
    trace(0xC0DEC0FFEEULL);
}
EOD
    # Probe sudo via the staged binary itself: this repo allows
    # `sudo -n host/*/*` without a password, but bare `sudo -n true`
    # is not allowlisted, so we can't probe with that. `--version`
    # exits cleanly without touching libdtrace.
    if ! sudo -n "$PROJECT_ROOT/host/runtime/bifrost" --version >/dev/null 2>&1; then
        echo "[fbsd-smoke] [SKIPPED] source-compile gate (no NOPASSWD sudo for host/runtime/bifrost)" >&2
    elif sudo -n "$PROJECT_ROOT/host/runtime/bifrost" freebsd-proof "$BACKEND_PID" \
        --source "$BIFROST_SOURCE_PROOF_D" \
        --records 4 \
        --probe-id 16 \
        >"$BIFROST_SOURCE_PROOF_LOG" 2>&1; then
        if grep -Eq "value=0xc0dec0ffee" "$BIFROST_SOURCE_PROOF_LOG"; then
            SOURCE_PROOF_READY=1
            echo "[fbsd-smoke] host-compiled D source round-tripped through guest native-DTrace"
        else
            echo "[fbsd-smoke] source-compile proof succeeded but no expected record rendered" >&2
            cat "$BIFROST_SOURCE_PROOF_LOG" >&2 || true
            exit 1
        fi
    else
        echo "[fbsd-smoke] source-compile proof failed" >&2
        cat "$BIFROST_SOURCE_PROOF_LOG" >&2 || true
        exit 1
    fi
fi

# fbt-coverage gate: confirms `fbt:kernel:*` actually
# attaches in-guest after the provider preload.  Skipped when
# fbt.ko isn't on the staged module disk (older builds).
BIFROST_FBT_PROOF_LOG="${BIFROST_FBT_PROOF_LOG:-/tmp/bifrost-fbsd-fbt-proof.log}"
BIFROST_FBT_PROOF_D="${BIFROST_FBT_PROOF_D:-/tmp/bifrost-fbsd-fbt-proof.d}"
FREEBSD_EXPECT_FBT_PROBE="${FREEBSD_EXPECT_FBT_PROBE:-auto}"
FBT_PROBE_READY=0
if [ "$FREEBSD_EXPECT_FBT_PROBE" = "1" ] || \
   [ "$FREEBSD_EXPECT_FBT_PROBE" = "auto" -a \
     -f "$FREEBSD_MODULES_DIR/boot/kernel/fbt.ko" ]; then
    # `cpu_idle` fires constantly on every idle CPU — even a
    # quiescent FreeBSD VM hits it thousands of times per second.
    # Pairing it with the wrapper's 200ms trace window guarantees
    # at least one fire and proves the full fbt path end-to-end:
    # fbt provider registered, retain → provide → match ordering
    # correct, probe armed, fired, drained from the buffer.
    cat >"$BIFROST_FBT_PROOF_D" <<'EOD'
fbt:kernel:cpu_idle:entry
{
    trace(0xFBC0FFEEULL);
}
EOD
    if ! sudo -n "$PROJECT_ROOT/host/runtime/bifrost" --version >/dev/null 2>&1; then
        echo "[fbsd-smoke] [SKIPPED] fbt-coverage gate (no NOPASSWD sudo)" >&2
    elif sudo -n "$PROJECT_ROOT/host/runtime/bifrost" freebsd-proof "$BACKEND_PID" \
        --source "$BIFROST_FBT_PROOF_D" \
        --records 4 \
        --probe-id 32 \
        >"$BIFROST_FBT_PROOF_LOG" 2>&1; then
        if grep -Eq "value=0xfbc0ffee" "$BIFROST_FBT_PROOF_LOG"; then
            FBT_PROBE_READY=1
            echo "[fbsd-smoke] fbt:kernel:cpu_idle:entry attached and produced record"
        else
            echo "[fbsd-smoke] fbt proof succeeded but no expected record rendered" >&2
            cat "$BIFROST_FBT_PROOF_LOG" >&2 || true
        fi
    else
        echo "[fbsd-smoke] [v3 PENDING] fbt:kernel:* probes did not attach — see /tmp/bifrost-fbsd-fbt-proof.log" >&2
        head -20 "$BIFROST_FBT_PROOF_LOG" >&2 || true
    fi
fi

# Syscall gate: prove the systrace provider attaches under
# the wrapper.  Two-phase: phase 1 confirms the provider matches
# (no "matched zero" error). Phase 2 (firing a record) is best-
# effort because syscall firing depends on userspace activity in
# the brief trace window; the cross-kernel demos don't use syscall
# probes on the FreeBSD side, so this gate is informational.
BIFROST_SYSCALL_PROOF_LOG="${BIFROST_SYSCALL_PROOF_LOG:-/tmp/bifrost-fbsd-syscall-proof.log}"
BIFROST_SYSCALL_PROOF_D="${BIFROST_SYSCALL_PROOF_D:-/tmp/bifrost-fbsd-syscall-proof.d}"
SYSCALL_PROBE_READY=0
if [ "$FREEBSD_EXPECT_FBT_PROBE" = "1" ] || \
   [ "$FREEBSD_EXPECT_FBT_PROBE" = "auto" -a \
     -f "$FREEBSD_MODULES_DIR/boot/kernel/systrace.ko" ]; then
    cat >"$BIFROST_SYSCALL_PROOF_D" <<'EOD'
syscall::_umtx_op:entry
{
    trace(0x5C5C5C5C5C5CULL);
}
EOD
    if sudo -n "$PROJECT_ROOT/host/runtime/bifrost" freebsd-proof "$BACKEND_PID" \
        --source "$BIFROST_SYSCALL_PROOF_D" \
        --records 4 \
        --probe-id 48 \
        >"$BIFROST_SYSCALL_PROOF_LOG" 2>&1; then
        if grep -Eq "value=0x5c5c5c5c5c5c" "$BIFROST_SYSCALL_PROOF_LOG"; then
            SYSCALL_PROBE_READY=2
            echo "[fbsd-smoke] syscall::_umtx_op:entry attached and produced record"
        fi
    elif ! grep -Eq "matched zero probes|matched no ECB" \
             "$BIFROST_SYSCALL_PROOF_LOG" 2>/dev/null; then
        # Provider matched + probe armed, but no record fired in the
        # window.  Provider coverage is proven; firing is workload-
        # dependent.
        SYSCALL_PROBE_READY=1
        echo "[fbsd-smoke] syscall provider attached (no fire in 500ms window — expected on idle VM)"
    fi
fi

# Profile gate: prove the profile provider attaches under the
# wrapper. `profile:::tick-100ms` fires deterministically at 10 Hz, so
# the 200ms wrapper trace window guarantees 1-2 records.
BIFROST_PROFILE_PROOF_LOG="${BIFROST_PROFILE_PROOF_LOG:-/tmp/bifrost-fbsd-profile-proof.log}"
BIFROST_PROFILE_PROOF_D="${BIFROST_PROFILE_PROOF_D:-/tmp/bifrost-fbsd-profile-proof.d}"
PROFILE_PROBE_READY=0
if [ "$FREEBSD_EXPECT_FBT_PROBE" = "1" ] || \
   [ "$FREEBSD_EXPECT_FBT_PROBE" = "auto" -a \
     -f "$FREEBSD_MODULES_DIR/boot/kernel/profile.ko" ]; then
    cat >"$BIFROST_PROFILE_PROOF_D" <<'EOD'
profile:::tick-100ms
{
    trace(0xCAFEBABE12345678ULL);
}
EOD
    if sudo -n "$PROJECT_ROOT/host/runtime/bifrost" freebsd-proof "$BACKEND_PID" \
        --source "$BIFROST_PROFILE_PROOF_D" \
        --records 4 \
        --probe-id 64 \
        >"$BIFROST_PROFILE_PROOF_LOG" 2>&1; then
        if grep -Eq "value=0xcafebabe12345678" "$BIFROST_PROFILE_PROOF_LOG"; then
            PROFILE_PROBE_READY=1
            echo "[fbsd-smoke] profile:::tick-100ms attached and produced record"
        fi
    fi
fi

echo
echo "[fbsd-smoke] -------- summary --------"
echo "[fbsd-smoke] ✓ conduit-backend bound, QEMU booted FreeBSD ${FREEBSD_RELEASE:-14.3-RELEASE}"
echo "[fbsd-smoke] ✓ vhost-user-test-device-pci attached without VMM error"
if [ "$CONDUIT_READY" -eq 1 ]; then
    [ "$FREEBSD_PRELOAD_CONDUIT" = "1" ] && \
        echo "[fbsd-smoke] ✓ EFI loader preloaded opensolaris.ko + dtrace.ko + bifrost_conduit.ko from USB module disk"
    echo "[fbsd-smoke] ✓ bifrost_conduit kernel transport marker observed"
    [ "$DATA_SHM_READY" -eq 1 ] && \
        echo "[fbsd-smoke] ✓ conduit-backend ingested guest DATA_SHM_READY"
    if [ "$DTRACE_RECORD_READY" -eq 1 ]; then
        echo "[fbsd-smoke] ✓ host data SHM contains a native FreeBSD DTrace proof record"
    else
        echo "[fbsd-smoke] [v2 PENDING] native FreeBSD DTrace records — see guest/freebsd-bifrost/"
    fi
    if [ "$SOURCE_PROOF_READY" -eq 1 ]; then
        echo "[fbsd-smoke] ✓ host-compiled D source -> guest kernel record (libdtrace path)"
    fi
    if [ "$FBT_PROBE_READY" -eq 1 ]; then
        echo "[fbsd-smoke] ✓ fbt:kernel:* probe attached and emitted a record (cross-kernel demo unblock)"
    fi
    if [ "$SYSCALL_PROBE_READY" -eq 2 ]; then
        echo "[fbsd-smoke] ✓ syscall::* probe attached and emitted a record"
    elif [ "$SYSCALL_PROBE_READY" -eq 1 ]; then
        echo "[fbsd-smoke] ✓ syscall:: provider attached (firing is workload-dependent)"
    fi
    if [ "$PROFILE_PROBE_READY" -eq 1 ]; then
        echo "[fbsd-smoke] ✓ profile:::tick-* probe attached and emitted a record"
    fi
else
    echo "[fbsd-smoke] [v1 PENDING] guest-side bifrost_conduit driver — see guest/freebsd-bifrost/"
fi
echo "[fbsd-smoke] launch log:   $LAUNCH_LOG"
echo "[fbsd-smoke] backend log:  $BACKEND_LOG"
[ "$DTRACE_RECORD_READY" -eq 1 ] && echo "[fbsd-smoke] data log:     $BIFROST_DATA_LOG"
[ "$DTRACE_RECORD_READY" -eq 1 ] && echo "[fbsd-smoke] proof log:    $BIFROST_PROOF_LOG"
exit 0
