#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# qemu-launch-freebsd.sh — boot a stock FreeBSD aarch64 cloud image
# under the custom QEMU with conduit-backend attached via
# vhost-user-test-device-pci.
#
# This is the FreeBSD-first kernel-only guest harness. The host
# layer is unchanged from the Linux smolvm/QEMU path — same
# conduit-backend binary, same data SHM contract. The differences
# are entirely in the guest:
#
#   * unmodified FreeBSD root image (a stock release QCOW2);
#   * UEFI/EDK2 boot rather than direct kernel boot;
#   * virtio-pci, not virtio-mmio (FreeBSD's cloud images expect
#     ACPI + virtio-pci, and the custom QEMU ships
#     vhost-user-test-device-pci so the same conduit transport
#     attaches without changes).
#
# v0 prove-out: this script verifies QEMU can boot FreeBSD with
# the conduit chardev attached and conduit-backend stays alive.
# The in-guest bifrost_conduit driver lands separately under
# guest/freebsd-bifrost/.
#
# Required environment:
#   QEMU                 absolute path to the custom QEMU binary
#                        (must expose vhost-user-test-device-pci
#                        and memory-backend-shm). Defaults to
#                        /private/tmp/qemu-11.0.0/build/qemu-system-aarch64
#                        which is the verified build for this
#                        project; override if you've built it
#                        somewhere else.
#
# Optional environment:
#   FREEBSD_QCOW2        path to FreeBSD 14.3 aarch64 cloud QCOW2.
#                        Auto-cached under artifacts/freebsd/ if
#                        unset and FREEBSD_QCOW2_URL is reachable.
#   FREEBSD_QCOW2_SNAPSHOT
#                        default 1. Boot through a per-launch qcow2
#                        overlay and delete it on exit so the cached
#                        release image remains pristine.
#   QEMU_IMG             qemu-img binary for creating the temporary
#                        overlay. Defaults to qemu-img on PATH.
#   FREEBSD_MODULES_DIR  optional staged module disk directory. When
#                        set, the launcher copies it to a per-launch
#                        temporary vvfat tree and exposes that as a
#                        second virtio-blk device. This does not mutate
#                        the root image or the staged source directory.
#   FREEBSD_MODULES_BUS  virtio or usb, default virtio. Use usb when
#                        the FreeBSD EFI loader must see the module
#                        disk before the kernel starts.
#   FREEBSD_WORKLOAD_DIR optional staged workload disk directory.
#                        When set, the launcher copies it to a
#                        per-launch vvfat tree and exposes it as a
#                        third virtio-blk device (typically /dev/da1
#                        in the guest).  Use the
#                        host/runtime/build-freebsd-workload-disk.sh
#                        helper to stage nginx/postgres/pgbench
#                        pkg tarballs into this dir.
#   QEMU_QMP_SOCK        optional QMP unix socket. Used by smoke tests
#                        that need to inject EFI keyboard events before
#                        the FreeBSD kernel starts.
#   FREEBSD_EFI_KEYBOARD optional 0/1. Attach a USB keyboard for EFI
#                        loader automation. Defaults to 1 when
#                        QEMU_QMP_SOCK is set, otherwise 0.
#   FREEBSD_QCOW2_URL    download URL for the QCOW2.xz. Defaults
#                        to the official FreeBSD VM-IMAGES path.
#   FREEBSD_EDK2_CODE    EDK2 read-only code firmware. Defaults
#                        to /opt/homebrew/share/qemu/edk2-aarch64-code.fd
#   FREEBSD_EDK2_VARS    EDK2 variable template (per-VM copy is
#                        made under artifacts/freebsd/). Defaults
#                        to /opt/homebrew/share/qemu/edk2-arm-vars.fd

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACTS_DIR="$PROJECT_ROOT/artifacts/freebsd"
mkdir -p "$ARTIFACTS_DIR"

SOCK="${CONDUIT_SOCK:-/tmp/conduit-fbsd-$$.sock}"
LOG="${CONDUIT_LOG:-/tmp/conduit-backend-fbsd.log}"
QEMU_LOG="${QEMU_LOG:-/tmp/qemu-freebsd.log}"
WAIT_MS="${CONDUIT_WAIT_MS:-5000}"
DATA_SHM_NAME="${CONDUIT_DATA_SHM_NAME:-/conduit-fbsd-data-$$}"
BACKEND_PID_FILE="${CONDUIT_BACKEND_PID_FILE:-}"
QEMU_PID_FILE="${QEMU_PID_FILE:-}"
QEMU_TRACE_EVENTS="${QEMU_TRACE_EVENTS:-}"
QEMU_QMP_SOCK="${QEMU_QMP_SOCK:-}"
FREEBSD_MODULES_DIR="${FREEBSD_MODULES_DIR:-}"
# Default the module disk to the well-known staged path when the
# operator hasn't been more specific.  The orchestrator's
# `bifrost orchestrate` spawn path doesn't pass FREEBSD_MODULES_DIR
# explicitly — without this default the EFI preload "succeeds" (the
# QMP type-text path completes) but the loader can't actually find
# disk1s1:/boot/kernel/dtrace.ko, so the guest boots without
# bifrost_conduit and every LOAD_PROG times out at the host side
# 30+ s later with no useful diagnostic.
if [ -z "$FREEBSD_MODULES_DIR" ] \
    && [ -d "$PROJECT_ROOT/artifacts/freebsd/module-disk/boot/kernel" ]; then
    FREEBSD_MODULES_DIR="$PROJECT_ROOT/artifacts/freebsd/module-disk"
fi
# Default to the `usb` bus for the same reason: the EFI loader sees
# USB-backed disks during its early-boot probe, but the virtio-blk
# bus isn't enumerated until after the kernel takes over, so
# `load disk1s1:/boot/kernel/dtrace.ko` from the loader prompt only
# works when the modules sit on a USB device.
FREEBSD_MODULES_BUS="${FREEBSD_MODULES_BUS:-usb}"
FREEBSD_MODULES_RUN_DIR=""
FREEBSD_WORKLOAD_DIR="${FREEBSD_WORKLOAD_DIR:-}"
FREEBSD_WORKLOAD_RUN_DIR=""
FREEBSD_EFI_KEYBOARD="${FREEBSD_EFI_KEYBOARD:-}"

ARCH="$(uname -m)"
OS="$(uname -s)"

case "$ARCH" in
    arm64|aarch64) ARCH=aarch64 ;;
    *)
        echo "[fbsd-launch] this harness targets aarch64 hosts; got $ARCH" >&2
        echo "[fbsd-launch] (FreeBSD x86_64 v0 is out of scope — vhost-user-test-device-pci works either way, but HVF is aarch64-only)" >&2
        exit 1
        ;;
esac

case "$OS" in
    Darwin) DEFAULT_ACCEL=hvf ;;
    Linux)  DEFAULT_ACCEL=kvm ;;
    *)
        echo "[fbsd-launch] unsupported OS $OS" >&2
        exit 1
        ;;
esac

ACCEL="${QEMU_ACCEL:-$DEFAULT_ACCEL}"
QEMU="${QEMU:-/private/tmp/qemu-11.0.0/build/qemu-system-aarch64}"
MEMORY="${QEMU_MEMORY:-4096M}"
SMP="${QEMU_SMP:-2}"
DEVICE="${QEMU_VHOST_DEVICE:-vhost-user-test-device-pci}"
VIRTIO_ID="${QEMU_VIRTIO_ID:-45}"
VQ_SIZE="${QEMU_VQ_SIZE:-1024}"

FREEBSD_RELEASE="${FREEBSD_RELEASE:-14.3-RELEASE}"
FREEBSD_QCOW2_URL_DEFAULT="https://download.freebsd.org/releases/VM-IMAGES/${FREEBSD_RELEASE}/aarch64/Latest/FreeBSD-${FREEBSD_RELEASE}-arm64-aarch64.qcow2.xz"
FREEBSD_QCOW2_URL="${FREEBSD_QCOW2_URL:-$FREEBSD_QCOW2_URL_DEFAULT}"
FREEBSD_QCOW2="${FREEBSD_QCOW2:-$ARTIFACTS_DIR/FreeBSD-${FREEBSD_RELEASE}-arm64-aarch64.qcow2}"
FREEBSD_QCOW2_SNAPSHOT="${FREEBSD_QCOW2_SNAPSHOT:-1}"
FREEBSD_QCOW2_OVERLAY="${FREEBSD_QCOW2_OVERLAY:-$ARTIFACTS_DIR/freebsd-${FREEBSD_RELEASE}-overlay-$$.qcow2}"
QEMU_IMG="${QEMU_IMG:-qemu-img}"
if [ -z "$FREEBSD_EFI_KEYBOARD" ] && [ -n "$QEMU_QMP_SOCK" ]; then
    FREEBSD_EFI_KEYBOARD=1
fi
FREEBSD_EFI_KEYBOARD="${FREEBSD_EFI_KEYBOARD:-0}"

FREEBSD_EDK2_CODE="${FREEBSD_EDK2_CODE:-/opt/homebrew/share/qemu/edk2-aarch64-code.fd}"
FREEBSD_EDK2_VARS_SRC="${FREEBSD_EDK2_VARS:-/opt/homebrew/share/qemu/edk2-arm-vars.fd}"
FREEBSD_EDK2_VARS="$ARTIFACTS_DIR/edk2-arm-vars-$$.fd"

usage() {
    cat >&2 <<EOF
usage: host/runtime/qemu-launch-freebsd.sh [options]

options:
  --memory SIZE             guest memory size, default $MEMORY
  --smp N                   vCPU count, default $SMP
  --qcow2 PATH              FreeBSD aarch64 cloud QCOW2 image
  --socket PATH             vhost-user socket path

environment:
  QEMU                      QEMU binary (must be the custom build)
  QEMU_IMG                  qemu-img binary for temporary overlays
  FREEBSD_QCOW2             path to the cached/downloaded QCOW2
  FREEBSD_QCOW2_SNAPSHOT    default 1; use a disposable overlay
  FREEBSD_QCOW2_OVERLAY     override temporary overlay path
  FREEBSD_MODULES_DIR       optional read-only module disk directory
  FREEBSD_MODULES_BUS       virtio or usb module disk bus, default virtio
  QEMU_QMP_SOCK             optional QMP unix socket for loader automation
  FREEBSD_EFI_KEYBOARD      attach EFI-visible USB keyboard, default 1 with QMP
  FREEBSD_QCOW2_URL         override download URL
  FREEBSD_EDK2_CODE         EDK2 code firmware
  FREEBSD_EDK2_VARS         EDK2 vars template (copied per-VM)
  CONDUIT_BACKEND_PID_FILE  write conduit-backend pid for callers
  QEMU_PID_FILE             write QEMU pid for callers
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --memory) MEMORY="$2"; shift 2 ;;
        --smp)    SMP="$2";    shift 2 ;;
        --qcow2)  FREEBSD_QCOW2="$2"; shift 2 ;;
        --socket) SOCK="$2";   shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[fbsd-launch] unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

# QEMU prerequisites — fail fast and loud, per fbsd.md step 1.
if ! command -v "$QEMU" >/dev/null 2>&1 && [ ! -x "$QEMU" ]; then
    echo "[fbsd-launch] QEMU not found at $QEMU" >&2
    echo "[fbsd-launch] build qemu with --enable-vhost-user and point QEMU= at it" >&2
    exit 1
fi
DEVICE_HELP="$("$QEMU" -device help 2>/dev/null || true)"
if ! printf '%s\n' "$DEVICE_HELP" | grep -q "name \"$DEVICE\""; then
    echo "[fbsd-launch] $QEMU does not expose -device $DEVICE" >&2
    echo "[fbsd-launch] the FreeBSD harness REQUIRES vhost-user-test-device-pci; check your build config" >&2
    exit 1
fi
OBJECT_HELP="$("$QEMU" -object help 2>/dev/null || true)"
if ! printf '%s\n' "$OBJECT_HELP" | grep -q 'memory-backend-shm'; then
    echo "[fbsd-launch] $QEMU does not provide memory-backend-shm" >&2
    exit 1
fi

if [ ! -f "$FREEBSD_EDK2_CODE" ]; then
    echo "[fbsd-launch] EDK2 code firmware not found: $FREEBSD_EDK2_CODE" >&2
    echo "[fbsd-launch] install qemu (Homebrew ships it under share/qemu/) or set FREEBSD_EDK2_CODE" >&2
    exit 1
fi
if [ ! -f "$FREEBSD_EDK2_VARS_SRC" ]; then
    echo "[fbsd-launch] EDK2 vars template not found: $FREEBSD_EDK2_VARS_SRC" >&2
    exit 1
fi

# Download/cache the FreeBSD QCOW2 on demand. Skip if user supplied a path.
if [ ! -f "$FREEBSD_QCOW2" ]; then
    XZ_FILE="$ARTIFACTS_DIR/$(basename "$FREEBSD_QCOW2_URL")"
    if [ ! -f "$XZ_FILE" ]; then
        echo "[fbsd-launch] downloading $FREEBSD_QCOW2_URL" >&2
        if ! curl -fL --retry 3 -o "$XZ_FILE.part" "$FREEBSD_QCOW2_URL"; then
            echo "[fbsd-launch] download failed; provide FREEBSD_QCOW2 explicitly" >&2
            exit 1
        fi
        mv "$XZ_FILE.part" "$XZ_FILE"
    fi
    echo "[fbsd-launch] decompressing $(basename "$XZ_FILE") -> $(basename "$FREEBSD_QCOW2")" >&2
    xz -dk "$XZ_FILE" -c > "$FREEBSD_QCOW2.part"
    mv "$FREEBSD_QCOW2.part" "$FREEBSD_QCOW2"
fi

# Per-launch copy of the variable store; EDK2 writes to it on every boot.
cp "$FREEBSD_EDK2_VARS_SRC" "$FREEBSD_EDK2_VARS"

BOOT_QCOW2="$FREEBSD_QCOW2"
BOOT_QCOW2_FORMAT=qcow2
if [ "$FREEBSD_QCOW2_SNAPSHOT" != "0" ]; then
    if ! command -v "$QEMU_IMG" >/dev/null 2>&1 && [ ! -x "$QEMU_IMG" ]; then
        echo "[fbsd-launch] qemu-img not found at $QEMU_IMG" >&2
        echo "[fbsd-launch] set QEMU_IMG or FREEBSD_QCOW2_SNAPSHOT=0" >&2
        exit 1
    fi
    rm -f "$FREEBSD_QCOW2_OVERLAY"
    "$QEMU_IMG" create -q -f qcow2 -F qcow2 -b "$FREEBSD_QCOW2" "$FREEBSD_QCOW2_OVERLAY"
    BOOT_QCOW2="$FREEBSD_QCOW2_OVERLAY"
fi

cleanup() {
    if [ -n "${QEMU_PID:-}" ]; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    if [ -n "${BACKEND_PID:-}" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    rm -f "$SOCK" "$QEMU_QMP_SOCK" "$FREEBSD_EDK2_VARS"
    if [ "$FREEBSD_QCOW2_SNAPSHOT" != "0" ]; then
        rm -f "$FREEBSD_QCOW2_OVERLAY"
    fi
    [ -n "$FREEBSD_MODULES_RUN_DIR" ] && rm -rf "$FREEBSD_MODULES_RUN_DIR"
    [ -n "$FREEBSD_WORKLOAD_RUN_DIR" ] && rm -rf "$FREEBSD_WORKLOAD_RUN_DIR"
    [ -n "$BACKEND_PID_FILE" ] && rm -f "$BACKEND_PID_FILE"
    [ -n "$QEMU_PID_FILE" ] && rm -f "$QEMU_PID_FILE"
}
trap cleanup EXIT INT TERM

rm -f "$SOCK"
VIRTIO_CONDUIT_DATA_SHM_NAME="$DATA_SHM_NAME" \
    conduit-backend --socket "$SOCK" >"$LOG" 2>&1 &
BACKEND_PID=$!
[ -n "$BACKEND_PID_FILE" ] && printf '%s\n' "$BACKEND_PID" >"$BACKEND_PID_FILE"

WAITED=0
while [ ! -S "$SOCK" ]; do
    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo "[fbsd-launch] conduit-backend exited before binding $SOCK" >&2
        tail -n 20 "$LOG" >&2 || true
        exit 1
    fi
    if [ "$WAITED" -ge "$WAIT_MS" ]; then
        echo "[fbsd-launch] timed out waiting for $SOCK after ${WAIT_MS}ms" >&2
        exit 1
    fi
    sleep 0.05
    WAITED=$((WAITED + 50))
done

echo "[fbsd-launch] conduit-backend ready on $SOCK (pid $BACKEND_PID)" >&2
echo "[fbsd-launch] qcow2=$FREEBSD_QCOW2 qemu=$QEMU" >&2
if [ "$FREEBSD_QCOW2_SNAPSHOT" != "0" ]; then
    echo "[fbsd-launch] qcow2 overlay=$BOOT_QCOW2 (discarded on exit)" >&2
fi
echo "[fbsd-launch] conduit device=$DEVICE virtio-id=$VIRTIO_ID vq_size=$VQ_SIZE" >&2
if [ -n "$FREEBSD_MODULES_DIR" ]; then
    case "$FREEBSD_MODULES_BUS" in
        virtio|usb) ;;
        *)
            echo "[fbsd-launch] FREEBSD_MODULES_BUS must be virtio or usb, got: $FREEBSD_MODULES_BUS" >&2
            exit 1
            ;;
    esac
    if [ ! -d "$FREEBSD_MODULES_DIR" ]; then
        echo "[fbsd-launch] FREEBSD_MODULES_DIR is not a directory: $FREEBSD_MODULES_DIR" >&2
        exit 1
    fi
    if [ ! -f "$FREEBSD_MODULES_DIR/boot/kernel/opensolaris.ko" ]; then
        echo "[fbsd-launch] FREEBSD_MODULES_DIR missing boot/kernel/opensolaris.ko: $FREEBSD_MODULES_DIR" >&2
        exit 1
    fi
    if [ ! -f "$FREEBSD_MODULES_DIR/boot/kernel/dtrace.ko" ]; then
        echo "[fbsd-launch] FREEBSD_MODULES_DIR missing boot/kernel/dtrace.ko: $FREEBSD_MODULES_DIR" >&2
        exit 1
    fi
    if [ ! -f "$FREEBSD_MODULES_DIR/boot/kernel/bifrost_conduit.ko" ]; then
        echo "[fbsd-launch] FREEBSD_MODULES_DIR missing boot/kernel/bifrost_conduit.ko: $FREEBSD_MODULES_DIR" >&2
        exit 1
    fi
    FREEBSD_MODULES_RUN_DIR="$ARTIFACTS_DIR/module-disk-run-$$"
    rm -rf "$FREEBSD_MODULES_RUN_DIR"
    cp -R "$FREEBSD_MODULES_DIR" "$FREEBSD_MODULES_RUN_DIR"
    echo "[fbsd-launch] module disk=$FREEBSD_MODULES_DIR bus=$FREEBSD_MODULES_BUS (vvfat copy $FREEBSD_MODULES_RUN_DIR)" >&2
fi

if [ -n "$FREEBSD_WORKLOAD_DIR" ]; then
    if [ ! -d "$FREEBSD_WORKLOAD_DIR" ]; then
        echo "[fbsd-launch] FREEBSD_WORKLOAD_DIR is not a directory: $FREEBSD_WORKLOAD_DIR" >&2
        exit 1
    fi
    FREEBSD_WORKLOAD_RUN_DIR="$ARTIFACTS_DIR/workload-disk-run-$$"
    rm -rf "$FREEBSD_WORKLOAD_RUN_DIR"
    cp -R "$FREEBSD_WORKLOAD_DIR" "$FREEBSD_WORKLOAD_RUN_DIR"
    echo "[fbsd-launch] workload disk=$FREEBSD_WORKLOAD_DIR (vvfat copy $FREEBSD_WORKLOAD_RUN_DIR)" >&2
fi

TRACE_ARGS=()
if [ -n "$QEMU_TRACE_EVENTS" ]; then
    IFS=', ' read -r -a TRACE_EVENTS <<< "$QEMU_TRACE_EVENTS"
    for event in "${TRACE_EVENTS[@]}"; do
        [ -n "$event" ] && TRACE_ARGS+=("-trace" "$event")
    done
fi

# FreeBSD's stock cloud image boots from the ESP partition via EDK2.
# memory-backend-shm is required so the conduit-backend's PFN
# mirror path can resolve guest physical addresses to host
# mappings. virtio-blk-pci (rather than virtio-blk-device) keeps
# the standard cloud image happy.
QEMU_CPU="${QEMU_CPU:-host}"
QEMU_ARGS=(
    -accel "$ACCEL"
    -machine "virt,gic-version=3,memory-backend=mem"
    -cpu "$QEMU_CPU"
    -smp "$SMP"
    -m "$MEMORY"
    -object "memory-backend-shm,id=mem,share=on,size=$MEMORY"
    -drive "if=pflash,format=raw,readonly=on,file=$FREEBSD_EDK2_CODE"
    -drive "if=pflash,format=raw,file=$FREEBSD_EDK2_VARS"
    -drive "file=$BOOT_QCOW2,if=none,id=hd0,format=$BOOT_QCOW2_FORMAT"
    -device "virtio-blk-pci,drive=hd0,bootindex=1"
    -chardev "socket,id=conduit,path=$SOCK"
    -device "$DEVICE,chardev=conduit,virtio-id=$VIRTIO_ID,num_vqs=3,vq_size=$VQ_SIZE"
    -no-reboot
    -nographic
    -serial mon:stdio
)
if [ -n "$FREEBSD_MODULES_DIR" ]; then
    QEMU_ARGS+=(
        -drive "file=fat:rw:$FREEBSD_MODULES_RUN_DIR,if=none,id=mods,format=raw"
    )
fi
if [ -n "$FREEBSD_WORKLOAD_DIR" ]; then
    QEMU_ARGS+=(
        -drive "file=fat:rw:$FREEBSD_WORKLOAD_RUN_DIR,if=none,id=workload,format=raw"
        -device "virtio-blk-pci,drive=workload"
    )
fi
if [ "$FREEBSD_EFI_KEYBOARD" != "0" ] ||
    { [ -n "$FREEBSD_MODULES_DIR" ] && [ "$FREEBSD_MODULES_BUS" = "usb" ]; }; then
    QEMU_ARGS+=(
        -device "qemu-xhci"
    )
fi
if [ -n "$FREEBSD_MODULES_DIR" ]; then
    case "$FREEBSD_MODULES_BUS" in
        virtio)
            QEMU_ARGS+=(
                -device "virtio-blk-pci,drive=mods"
            )
            ;;
        usb)
            QEMU_ARGS+=(
                -device "usb-storage,drive=mods,bootindex=2"
            )
            ;;
    esac
fi
if [ "$FREEBSD_EFI_KEYBOARD" != "0" ]; then
    QEMU_ARGS+=(
        -device "usb-kbd"
    )
fi
if [ -n "$QEMU_QMP_SOCK" ]; then
    rm -f "$QEMU_QMP_SOCK"
    QEMU_ARGS+=(
        -qmp "unix:$QEMU_QMP_SOCK,server=on,wait=off"
    )
fi
# QEMU_GDB_PORT exposes the in-QEMU gdb remote on TCP, allowing
# lldb (or aarch64-elf-gdb) to attach and inspect guest-kernel
# state directly — used for debugging conduit/run_dof hangs that
# never surface a response on the wire.
if [ -n "${QEMU_GDB_PORT:-}" ]; then
    QEMU_ARGS+=(
        -gdb "tcp::${QEMU_GDB_PORT}"
    )
fi
if [ "${#TRACE_ARGS[@]}" -gt 0 ]; then
    QEMU_ARGS+=("${TRACE_ARGS[@]}")
fi

"$QEMU" "${QEMU_ARGS[@]}" &
QEMU_PID=$!
[ -n "$QEMU_PID_FILE" ] && printf '%s\n' "$QEMU_PID" >"$QEMU_PID_FILE"

set +e
wait "$QEMU_PID"
QEMU_STATUS=$?
set -e
QEMU_PID=""
exit "$QEMU_STATUS"
