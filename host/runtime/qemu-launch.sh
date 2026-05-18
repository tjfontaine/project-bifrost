#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# qemu-launch.sh — run the Bifrost guest under QEMU with the same
# out-of-process conduit-backend used by smolvm.
#
# The Bifrost kernel is built without PCI, so the QEMU path uses
# the generic virtio-mmio vhost-user test frontend:
#
#   -device vhost-user-test-device,chardev=conduit,virtio-id=45,num_vqs=3
#
# Stock Homebrew QEMU currently does not build this device on macOS.
# Build QEMU with `--enable-vhost-user` and point QEMU at that binary.
#
#   QEMU=/tmp/qemu-11.0.0/build/qemu-system-aarch64 \
#       host/runtime/qemu-launch.sh

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SOCK="${CONDUIT_SOCK:-/tmp/conduit-qemu-$$.sock}"
LOG="${CONDUIT_LOG:-/tmp/conduit-backend-qemu.log}"
WAIT_MS="${CONDUIT_WAIT_MS:-5000}"
DATA_SHM_NAME="${CONDUIT_DATA_SHM_NAME:-/conduit-qemu-data-$$}"
BACKEND_PID_FILE="${CONDUIT_BACKEND_PID_FILE:-}"
QEMU_PID_FILE="${QEMU_PID_FILE:-}"
QEMU_TRACE_EVENTS="${QEMU_TRACE_EVENTS:-}"

ARCH="$(uname -m)"
OS="$(uname -s)"

case "$ARCH" in
    arm64|aarch64)
        ARCH=aarch64
        KERNEL_ARCH=arm64
        DEFAULT_KERNEL="$PROJECT_ROOT/third_party/smolvm/libkrunfw/linux-6.12.76/arch/arm64/boot/Image"
        ;;
    x86_64|amd64)
        ARCH=x86_64
        KERNEL_ARCH=x86
        DEFAULT_KERNEL="$PROJECT_ROOT/third_party/smolvm/libkrunfw/linux-6.12.76/arch/x86/boot/bzImage"
        ;;
    *)
        echo "[qemu-launch] unsupported arch $ARCH" >&2
        exit 1
        ;;
esac

case "$OS" in
    Darwin)
        DEFAULT_ACCEL=hvf
        ;;
    Linux)
        DEFAULT_ACCEL=kvm
        ;;
    *)
        echo "[qemu-launch] unsupported OS $OS" >&2
        exit 1
        ;;
esac

ACCEL="${QEMU_ACCEL:-$DEFAULT_ACCEL}"
QEMU="${QEMU:-qemu-system-$ARCH}"
KERNEL="${QEMU_KERNEL:-${QEMU_VMLINUX:-$DEFAULT_KERNEL}}"
ROOTFS="${QEMU_ROOTFS:-$PROJECT_ROOT/artifacts/qemu-rootfs/redis-7-alpine.ext4}"
MEMORY="${QEMU_MEMORY:-8192M}"
SMP="${QEMU_SMP:-4}"
DEVICE="${QEMU_VHOST_DEVICE:-vhost-user-test-device}"
VIRTIO_ID="${QEMU_VIRTIO_ID:-45}"
VQ_SIZE="${QEMU_VQ_SIZE:-1024}"
TRANSPORTS="${QEMU_VIRTIO_MMIO_TRANSPORTS:-8}"
HIGHMEM="${QEMU_HIGHMEM:-on}"
APPEND="${QEMU_APPEND:-console=ttyAMA0 root=/dev/vda rw rootfstype=ext4 init=/usr/local/bin/redis-server -- --ignore-warnings ARM64-COW-BUG --protected-mode no --bind 0.0.0.0}"

usage() {
    cat >&2 <<EOF
usage: host/runtime/qemu-launch.sh [options]

options:
  --accel hvf|kvm|tcg       override accelerator
  --memory SIZE             guest memory size, default $MEMORY
  --smp N                   vCPU count, default $SMP
  --kernel PATH             bifrost-patched kernel Image/bzImage
  --rootfs PATH             ext4 root image from scripts/build-qemu-rootfs.sh
  --append CMDLINE          kernel command line
  --socket PATH             vhost-user socket path

environment:
  QEMU                      QEMU binary, default qemu-system-$ARCH
  QEMU_VIRTIO_ID            virtio id for stock QEMU, default $VIRTIO_ID
  QEMU_VQ_SIZE              virtqueue size, default $VQ_SIZE
  QEMU_TRACE_EVENTS         comma/space-separated QEMU trace events
  CONDUIT_BACKEND_PID_FILE write conduit-backend pid for callers
  QEMU_PID_FILE             write QEMU pid for callers
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --accel)
            ACCEL="$2"
            shift 2
            ;;
        --memory)
            MEMORY="$2"
            shift 2
            ;;
        --smp)
            SMP="$2"
            shift 2
            ;;
        --kernel|--vmlinux)
            KERNEL="$2"
            shift 2
            ;;
        --rootfs)
            ROOTFS="$2"
            shift 2
            ;;
        --append)
            APPEND="$2"
            shift 2
            ;;
        --socket)
            SOCK="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[qemu-launch] unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "[qemu-launch] $QEMU not on PATH" >&2
    echo "[qemu-launch] set QEMU=/path/to/qemu-system-$ARCH built with --enable-vhost-user" >&2
    exit 1
fi

if [ ! -f "$KERNEL" ]; then
    echo "[qemu-launch] kernel image not found: $KERNEL" >&2
    echo "[qemu-launch] set QEMU_KERNEL or QEMU_VMLINUX to the bifrost-patched kernel Image" >&2
    exit 1
fi

if [ ! -f "$ROOTFS" ]; then
    echo "[qemu-launch] rootfs image not found: $ROOTFS" >&2
    echo "[qemu-launch] build it with scripts/build-qemu-rootfs.sh" >&2
    exit 1
fi

if ! "$QEMU" -device help 2>/dev/null | grep -q "name \"$DEVICE\""; then
    echo "[qemu-launch] $QEMU does not provide -device $DEVICE" >&2
    echo "[qemu-launch] Homebrew QEMU disables vhost_user on macOS by default;" >&2
    echo "[qemu-launch] build QEMU with --enable-vhost-user and set QEMU=/path/to/qemu-system-$ARCH" >&2
    exit 1
fi

if ! "$QEMU" -object help 2>/dev/null | grep -q 'memory-backend-shm'; then
    echo "[qemu-launch] $QEMU does not provide memory-backend-shm" >&2
    exit 1
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
    rm -f "$SOCK"
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
        echo "[qemu-launch] conduit-backend exited before binding $SOCK" >&2
        echo "[qemu-launch] last log lines:" >&2
        tail -n 20 "$LOG" >&2 || true
        exit 1
    fi
    if [ "$WAITED" -ge "$WAIT_MS" ]; then
        echo "[qemu-launch] timed out waiting for $SOCK after ${WAIT_MS}ms" >&2
        exit 1
    fi
    sleep 0.05
    WAITED=$((WAITED + 50))
done

echo "[qemu-launch] conduit-backend ready on $SOCK (pid $BACKEND_PID)" >&2
echo "[qemu-launch] kernel=$KERNEL rootfs=$ROOTFS qemu=$QEMU" >&2
echo "[qemu-launch] conduit virtio-id=$VIRTIO_ID vq_size=$VQ_SIZE" >&2

TRACE_ARGS=()
if [ -n "$QEMU_TRACE_EVENTS" ]; then
    IFS=', ' read -r -a TRACE_EVENTS <<< "$QEMU_TRACE_EVENTS"
    for event in "${TRACE_EVENTS[@]}"; do
        [ -n "$event" ] && TRACE_ARGS+=("-trace" "$event")
    done
fi

QEMU_ARGS=(
    -accel "$ACCEL" \
    -machine "virt,virtio-mmio-transports=$TRANSPORTS,highmem=$HIGHMEM,memory-backend=mem" \
    -cpu host \
    -smp "$SMP" \
    -m "$MEMORY" \
    -object "memory-backend-shm,id=mem,share=on,size=$MEMORY" \
    -kernel "$KERNEL" \
    -drive "file=$ROOTFS,format=raw,if=none,id=root" \
    -device "virtio-blk-device,drive=root" \
    -append "$APPEND" \
    -chardev "socket,id=conduit,path=$SOCK" \
    -device "$DEVICE,chardev=conduit,virtio-id=$VIRTIO_ID,num_vqs=3,vq_size=$VQ_SIZE" \
    -no-reboot \
    -nographic \
    -serial mon:stdio
)
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
