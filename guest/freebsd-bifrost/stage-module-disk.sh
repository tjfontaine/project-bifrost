#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Stage a read-only module disk tree for qemu-launch-freebsd.sh.
#
# The launcher exposes this directory through QEMU's vvfat block backend when
# FREEBSD_MODULES_DIR points at it. This keeps the release qcow2 pristine while
# giving the FreeBSD loader/runtime an immutable place to find the proof
# modules without mutating the cached root image.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

OPENSOLARIS_KO="${FREEBSD_OPENSOLARIS_KO:-$PROJECT_ROOT/artifacts/freebsd/modules/opensolaris.ko}"
DTRACE_KO="${FREEBSD_DTRACE_KO:-$PROJECT_ROOT/artifacts/freebsd/modules/dtrace.ko}"
KO="${FREEBSD_BIFROST_KO:-$PROJECT_ROOT/artifacts/freebsd/modules/bifrost_conduit.ko}"
FBT_KO="${FREEBSD_FBT_KO:-$PROJECT_ROOT/artifacts/freebsd/modules/fbt.ko}"
SYSTRACE_KO="${FREEBSD_SYSTRACE_KO:-$PROJECT_ROOT/artifacts/freebsd/modules/systrace.ko}"
PROFILE_KO="${FREEBSD_PROFILE_KO:-$PROJECT_ROOT/artifacts/freebsd/modules/profile.ko}"
OUT_DIR="${FREEBSD_MODULES_DIR:-$PROJECT_ROOT/artifacts/freebsd/module-disk}"

fail() {
    echo "[freebsd-module-disk] $*" >&2
    exit 1
}

[ -f "$OPENSOLARIS_KO" ] || fail "missing module: $OPENSOLARIS_KO"
[ -f "$DTRACE_KO" ] || fail "missing module: $DTRACE_KO"
[ -f "$KO" ] || fail "missing module: $KO"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/boot/kernel" "$OUT_DIR/boot/defaults"

cp "$OPENSOLARIS_KO" "$OUT_DIR/boot/kernel/opensolaris.ko"
cp "$DTRACE_KO" "$OUT_DIR/boot/kernel/dtrace.ko"
cp "$KO" "$OUT_DIR/boot/kernel/bifrost_conduit.ko"

# Iter-9 provider modules.  Each is optional individually so a
# partial build still produces a usable disk; the smoke test
# preloads only the ones the demo's D source actually needs.
for entry in \
    "$FBT_KO:fbt.ko" \
    "$SYSTRACE_KO:systrace.ko" \
    "$PROFILE_KO:profile.ko"
do
    src="${entry%:*}"
    dst="${entry##*:}"
    if [ -f "$src" ]; then
        cp "$src" "$OUT_DIR/boot/kernel/$dst"
        echo "[freebsd-module-disk] staged provider $dst"
    else
        echo "[freebsd-module-disk] skipping provider $dst (no $src)" >&2
    fi
done

cat >"$OUT_DIR/boot/loader.conf" <<'EOF'
# Project Bifrost FreeBSD module preload candidate.
# This file is consumed only if the loader's currdev points at this staged
# module disk. The stock FreeBSD root qcow2 is not modified.
opensolaris_load="YES"
dtrace_load="YES"
bifrost_conduit_load="YES"
fbt_load="YES"
systrace_load="YES"
profile_load="YES"
EOF
cat >"$OUT_DIR/README.txt" <<'EOF'
Project Bifrost FreeBSD module disk.

Contents:
  /boot/kernel/opensolaris.ko
  /boot/kernel/dtrace.ko
  /boot/kernel/bifrost_conduit.ko
  /boot/kernel/fbt.ko        (optional)
  /boot/kernel/systrace.ko   (optional)
  /boot/kernel/profile.ko    (optional)
  /boot/loader.conf

Attach with:
  FREEBSD_MODULES_DIR=<this directory> host/runtime/qemu-launch-freebsd.sh

The base FreeBSD qcow2 remains unmodified. The current runtime harness still
needs a loader/preload command path before FREEBSD_EXPECT_CONDUIT=1 can pass.
EOF

echo "[freebsd-module-disk] staged $OUT_DIR"
