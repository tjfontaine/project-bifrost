#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Build a raw ext4 root disk from a Docker/OCI image for the QEMU
# smoke path. This is intentionally narrower than smolvm's full
# agent/container runtime: QEMU only needs a Linux userspace that can
# start the workload as pid 1 while the Bifrost guest driver talks to
# the host conduit device.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${QEMU_DOCKER_IMAGE:-redis:7-alpine}"
OUT="${QEMU_ROOTFS:-$PROJECT_ROOT/artifacts/qemu-rootfs/redis-7-alpine.ext4}"
TAR_OUT="${QEMU_ROOT_TAR:-${OUT%.ext4}.tar}"
BLOCKS="${QEMU_ROOTFS_BLOCKS:-262144}"
CONTAINER_NAME="bifrost-qemu-rootfs-$$"

if ! command -v docker >/dev/null 2>&1; then
    echo "[build-qemu-rootfs] docker not found" >&2
    exit 1
fi

if command -v mke2fs >/dev/null 2>&1; then
    MKE2FS="$(command -v mke2fs)"
elif [ -x /opt/homebrew/opt/e2fsprogs/sbin/mke2fs ]; then
    MKE2FS=/opt/homebrew/opt/e2fsprogs/sbin/mke2fs
else
    echo "[build-qemu-rootfs] mke2fs not found; install e2fsprogs" >&2
    exit 1
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/bifrost-qemu-rootfs.XXXXXX")"
cleanup() {
    docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$(dirname "$OUT")" "$(dirname "$TAR_OUT")"

echo "[build-qemu-rootfs] pulling $IMAGE" >&2
docker pull "$IMAGE" >/dev/null

echo "[build-qemu-rootfs] exporting $IMAGE" >&2
docker create --name "$CONTAINER_NAME" "$IMAGE" redis-server >/dev/null
docker export "$CONTAINER_NAME" -o "$TAR_OUT"
docker rm "$CONTAINER_NAME" >/dev/null

echo "[build-qemu-rootfs] unpacking rootfs" >&2
tar -xf "$TAR_OUT" -C "$TMPDIR"

echo "[build-qemu-rootfs] writing ext4 image $OUT" >&2
rm -f "$OUT"
"$MKE2FS" -q -F -t ext4 -L bifrost-root -d "$TMPDIR" "$OUT" "$BLOCKS"

echo "[build-qemu-rootfs] rootfs ready: $OUT" >&2
