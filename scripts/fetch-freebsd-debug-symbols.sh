#!/bin/sh
# Fetch unstripped FreeBSD aarch64 kernel from the release distribution
# and stash it alongside the project's unstripped .ko build outputs.
# These are the inputs gdb needs to symbolize a guest-kernel hang under
# qemu-system-aarch64 (HVF or TCG).  See fbsd.md for the
# debugging workflow.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE="${FREEBSD_RELEASE:-14.3-RELEASE}"
ARCH="${FREEBSD_ARCH:-aarch64}"
DIST_BASE="${FREEBSD_DIST_BASE:-https://download.freebsd.org/releases/arm64/${ARCH}/${RELEASE}}"
OUT_DIR="$PROJECT_ROOT/artifacts/freebsd/debug-symbols"
KTXZ="$OUT_DIR/kernel.txz"
KERNEL="$OUT_DIR/kernel"

OBJ_ROOT="$PROJECT_ROOT/artifacts/freebsd/obj"

mkdir -p "$OUT_DIR"

if [ ! -s "$KERNEL" ]; then
    echo "[debug-symbols] downloading kernel.txz from $DIST_BASE"
    curl -fsSL -o "$KTXZ" "$DIST_BASE/kernel.txz"
    echo "[debug-symbols] extracting ./boot/kernel/kernel"
    bsdtar -xf "$KTXZ" -C /tmp ./boot/kernel/kernel
    cp /tmp/boot/kernel/kernel "$KERNEL"
    chmod 0444 "$KERNEL"
    rm -f "$KTXZ" /tmp/boot/kernel/kernel
fi

# Refresh unstripped .ko copies from the build directory if present.
if [ -d "$OBJ_ROOT" ]; then
    echo "[debug-symbols] refreshing unstripped .ko symbols from $OBJ_ROOT"
    find "$OBJ_ROOT" -name "*.ko" -type f -print0 | xargs -0 -I{} cp {} "$OUT_DIR/"
fi

echo "[debug-symbols] ready in $OUT_DIR:"
ls -1 "$OUT_DIR"
echo
echo "Usage:"
echo "  aarch64-elf-gdb $OUT_DIR/kernel"
echo "  (gdb) target remote localhost:1234"
echo "  (gdb) add-symbol-file $OUT_DIR/dtrace.ko          <load-addr-from-kldstat>"
echo "  (gdb) add-symbol-file $OUT_DIR/bifrost_conduit.ko <load-addr-from-kldstat>"
