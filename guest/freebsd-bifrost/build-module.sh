#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Build the staged FreeBSD proof modules from the FreeBSD guest patch set.
#
# This script is intentionally separate from the runtime smoke test:
# build/provisioning may use host or FreeBSD userspace, while the trace
# acceptance path must not depend on a guest helper process or guest dtrace(1).

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FREEBSD_SRC="${FREEBSD_SRC:-$PROJECT_ROOT/third_party/freebsd-bifrost}"
FREEBSD_SRC_EXPECTED_BRANCH="${FREEBSD_SRC_EXPECTED_BRANCH:-bifrost/14.3}"
BUILD_ROOT="${BUILD_ROOT:-$PROJECT_ROOT/artifacts/freebsd/bifrost-module-build}"
OBJROOT="${OBJROOT:-$PROJECT_ROOT/artifacts/freebsd/obj}"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/artifacts/freebsd/modules}"
FREEBSD_TARGET="${FREEBSD_TARGET:-aarch64-unknown-freebsd14.3}"
FREEBSD_BUILD_PATHS="
Makefile
Makefile.inc1
share/mk
sys/dev/virtio
sys/modules/virtio
sys/modules/opensolaris
sys/modules/dtrace
sys/cddl/dev/fbt
sys/cddl/dev/systrace
sys/cddl/dev/profile
sys/conf
sys/kern
sys/sys
sys/vm
sys/arm64
sys/tools
sys/cddl
sys/compat/linuxkpi
sys/bsm
sys/security
sys/net
sys/netinet
sys/netinet6
sys/netpfil
sys/rpc
sys/crypto
sys/geom
sys/contrib/ck
sys/contrib/openzfs/include
sys/contrib/openzfs/module/os/freebsd/spl
sys/contrib/pcg-c
sys/ddb
sys/gdb
sys/kgssapi
cddl/contrib/opensolaris
"

fail() {
    echo "[freebsd-module-build] $*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 not found"
}

pick_cmd() {
    for cmd in "$@"; do
        if [ -n "$cmd" ] && command -v "$cmd" >/dev/null 2>&1; then
            command -v "$cmd"
            return 0
        fi
        if [ -n "$cmd" ] && [ -x "$cmd" ]; then
            printf '%s\n' "$cmd"
            return 0
        fi
    done
    return 1
}

[ -d "$FREEBSD_SRC" ] || fail "missing FreeBSD submodule: $FREEBSD_SRC (run: git submodule update --init --recursive third_party/freebsd-bifrost)"
[ -d "$FREEBSD_SRC/.git" ] || [ -f "$FREEBSD_SRC/.git" ] || \
    fail "FREEBSD_SRC=$FREEBSD_SRC is not a git checkout"

HOST_OS="$(uname -s)"
case "$HOST_OS" in
    FreeBSD)
        MAKE_CMD="${MAKE_CMD:-make}"
        MAKE_META_ARGS=""
        need_cmd "$MAKE_CMD"
        ;;
    Darwin|Linux)
        MAKE_CMD="${MAKE_CMD:-$(pick_cmd bmake)}" ||
            fail "bmake not found; install bmake or build on FreeBSD"
        FREEBSD_CC="${FREEBSD_CC:-$(pick_cmd /opt/homebrew/opt/llvm/bin/clang clang)}" ||
            fail "clang not found"
        FREEBSD_LD="${FREEBSD_LD:-$(pick_cmd ld.lld /opt/homebrew/bin/ld.lld)}" ||
            fail "ld.lld not found"
        FREEBSD_OBJCOPY="${FREEBSD_OBJCOPY:-$(pick_cmd llvm-objcopy /opt/homebrew/opt/llvm/bin/llvm-objcopy)}" ||
            fail "llvm-objcopy not found"
        MAKE_META_ARGS="-m $BUILD_ROOT/share/mk -m $BUILD_ROOT/sys/conf"
        ;;
    *)
        fail "unsupported host OS for module build: $HOST_OS"
        ;;
esac

rm -rf "$BUILD_ROOT" "$OBJROOT"
mkdir -p "$BUILD_ROOT" "$OBJROOT" "$OUT_DIR"

# Mirror the Linux model: the FreeBSD submodule's `bifrost/14.3`
# branch already carries the bifrost-conduit + dtrace-wrapper
# commits.  We just materialize the sparse subset bmake needs and
# build straight from it — no per-build patch-apply step.
if [ -d "$FREEBSD_SRC/.git" ] || [ -f "$FREEBSD_SRC/.git" ]; then
    branch="$(git -C "$FREEBSD_SRC" rev-parse --abbrev-ref HEAD)"
    if [ -n "$FREEBSD_SRC_EXPECTED_BRANCH" ] && [ "$branch" != "$FREEBSD_SRC_EXPECTED_BRANCH" ]; then
        fail "FREEBSD_SRC branch $branch != expected $FREEBSD_SRC_EXPECTED_BRANCH (run: git -C $FREEBSD_SRC checkout $FREEBSD_SRC_EXPECTED_BRANCH)"
    fi
    tar -C "$FREEBSD_SRC" -cf - $FREEBSD_BUILD_PATHS | tar -x -C "$BUILD_ROOT"
else
    # Non-git checkout (rare): plain copy.
    tar -C "$FREEBSD_SRC" -cf - . | tar -x -C "$BUILD_ROOT"
fi

build_extra_provider() {
    # Build a provider module (fbt / systrace / profile).  Same
    # toolchain selection as the existing dtrace.ko build, threaded
    # through both FreeBSD-host and cross-compile branches.
    name="$1"
    if [ "$HOST_OS" = "FreeBSD" ]; then
        env MAKEOBJDIRPREFIX="$OBJROOT" \
            "$MAKE_CMD" -C "$BUILD_ROOT/sys/modules/dtrace/$name" \
            SYSDIR="$BUILD_ROOT/sys" \
            MACHINE=arm64 \
            MACHINE_ARCH=aarch64
    else
        env MAKEOBJDIRPREFIX="$OBJROOT" \
            PATH="$(dirname "$FREEBSD_OBJCOPY"):$(dirname "$FREEBSD_LD"):$PATH" \
            "$MAKE_CMD" $MAKE_META_ARGS \
            -C "$BUILD_ROOT/sys/modules/dtrace/$name" \
            SYSDIR="$BUILD_ROOT/sys" \
            MACHINE=arm64 \
            MACHINE_ARCH=aarch64 \
            CC="$FREEBSD_CC -target $FREEBSD_TARGET" \
            LD="$FREEBSD_LD" \
            OBJCOPY="$FREEBSD_OBJCOPY"
    fi
}

if [ "$HOST_OS" = "FreeBSD" ]; then
    env MAKEOBJDIRPREFIX="$OBJROOT" \
        "$MAKE_CMD" -C "$BUILD_ROOT/sys/modules/opensolaris" \
        SYSDIR="$BUILD_ROOT/sys" \
        MACHINE=arm64 \
        MACHINE_ARCH=aarch64 \
        CFLAGS.spl_cmn_err.c+=-Wno-error=format \
        CFLAGS.spl_kmem.c+=-Wno-error=format \
        CFLAGS.spl_misc.c+=-Wno-error=pointer-sign
    env MAKEOBJDIRPREFIX="$OBJROOT" \
        "$MAKE_CMD" -C "$BUILD_ROOT/sys/modules/dtrace/dtrace" \
        SYSDIR="$BUILD_ROOT/sys" \
        MACHINE=arm64 \
        MACHINE_ARCH=aarch64
    env MAKEOBJDIRPREFIX="$OBJROOT" \
        "$MAKE_CMD" -C "$BUILD_ROOT/sys/modules/virtio/bifrost_conduit" \
        SYSDIR="$BUILD_ROOT/sys" \
        MACHINE=arm64 \
        MACHINE_ARCH=aarch64
else
    env MAKEOBJDIRPREFIX="$OBJROOT" \
        PATH="$(dirname "$FREEBSD_OBJCOPY"):$(dirname "$FREEBSD_LD"):$PATH" \
        "$MAKE_CMD" $MAKE_META_ARGS \
        -C "$BUILD_ROOT/sys/modules/opensolaris" \
        SYSDIR="$BUILD_ROOT/sys" \
        MACHINE=arm64 \
        MACHINE_ARCH=aarch64 \
        CC="$FREEBSD_CC -target $FREEBSD_TARGET" \
        LD="$FREEBSD_LD" \
        OBJCOPY="$FREEBSD_OBJCOPY" \
        CFLAGS.spl_cmn_err.c+=-Wno-error=format \
        CFLAGS.spl_kmem.c+=-Wno-error=format \
        CFLAGS.spl_misc.c+=-Wno-error=pointer-sign
    env MAKEOBJDIRPREFIX="$OBJROOT" \
        PATH="$(dirname "$FREEBSD_OBJCOPY"):$(dirname "$FREEBSD_LD"):$PATH" \
        "$MAKE_CMD" $MAKE_META_ARGS \
        -C "$BUILD_ROOT/sys/modules/dtrace/dtrace" \
        SYSDIR="$BUILD_ROOT/sys" \
        MACHINE=arm64 \
        MACHINE_ARCH=aarch64 \
        CC="$FREEBSD_CC -target $FREEBSD_TARGET" \
        LD="$FREEBSD_LD" \
        OBJCOPY="$FREEBSD_OBJCOPY"
    env MAKEOBJDIRPREFIX="$OBJROOT" \
        PATH="$(dirname "$FREEBSD_OBJCOPY"):$(dirname "$FREEBSD_LD"):$PATH" \
        "$MAKE_CMD" $MAKE_META_ARGS \
        -C "$BUILD_ROOT/sys/modules/virtio/bifrost_conduit" \
        SYSDIR="$BUILD_ROOT/sys" \
        MACHINE=arm64 \
        MACHINE_ARCH=aarch64 \
        CC="$FREEBSD_CC -target $FREEBSD_TARGET" \
        LD="$FREEBSD_LD" \
        OBJCOPY="$FREEBSD_OBJCOPY"
fi

# Provider modules for the cross-kernel demos: fbt (function
# boundary tracing — needed by `fbt:kernel:tcp_input:entry` etc.),
# systrace (syscall provider), profile (tick-Nsec / profile-Nsec).
# Each is a small standalone .ko built off the same SYSDIR — they
# register their providers with dtrace.ko at module load time, so
# preloading them in the EFI loader brings their probes into the
# match space for `dtrace_bifrost_run_dof`.
for provider in fbt systrace profile; do
    build_extra_provider "$provider"
done

opensolaris_ko="$(find "$OBJROOT" "$BUILD_ROOT/sys/modules/opensolaris" \
    -name opensolaris.ko -type f | head -1)"
dtrace_ko="$(find "$OBJROOT" "$BUILD_ROOT/sys/modules/dtrace/dtrace" \
    -name dtrace.ko -type f | head -1)"
ko="$(find "$OBJROOT" "$BUILD_ROOT/sys/modules/virtio/bifrost_conduit" \
    -name bifrost_conduit.ko -type f | head -1)"
[ -n "$opensolaris_ko" ] || fail "opensolaris.ko was not produced"
[ -n "$dtrace_ko" ] || fail "dtrace.ko was not produced"
[ -n "$ko" ] || fail "bifrost_conduit.ko was not produced"

cp "$opensolaris_ko" "$OUT_DIR/opensolaris.ko"
cp "$dtrace_ko" "$OUT_DIR/dtrace.ko"
cp "$ko" "$OUT_DIR/bifrost_conduit.ko"

# Stage every provider module that the cross-kernel demos
# rely on.  Each one is optional from the smoke test's perspective
# (if absent, the preload step skips it), but the build script is
# strict so a partial build doesn't ship a half-coverage drop.
for provider in fbt systrace profile; do
    src="$(find "$OBJROOT" "$BUILD_ROOT/sys/modules/dtrace/$provider" \
        -name "${provider}.ko" -type f | head -1)"
    [ -n "$src" ] || fail "${provider}.ko was not produced"
    cp "$src" "$OUT_DIR/${provider}.ko"
    echo "[freebsd-module-build] wrote $OUT_DIR/${provider}.ko"
done

echo "[freebsd-module-build] wrote $OUT_DIR/opensolaris.ko"
echo "[freebsd-module-build] wrote $OUT_DIR/dtrace.ko"
echo "[freebsd-module-build] wrote $OUT_DIR/bifrost_conduit.ko"

# Always mirror the unstripped (debug-symbol-bearing) .ko output into
# artifacts/freebsd/debug-symbols/ so aarch64-elf-gdb can resolve any
# kernel-side stack into module-level symbols without a separate
# regenerate step.  $OUT_DIR holds stripped copies (stage-module-disk
# ships those into the EFI module disk); the obj tree holds the
# unstripped twins that ELF DWARF info comes from.
DEBUG_SYM_DIR="$PROJECT_ROOT/artifacts/freebsd/debug-symbols"
mkdir -p "$DEBUG_SYM_DIR"
find "$OBJROOT" -name "*.ko" -type f -print0 |
    xargs -0 -I{} cp {} "$DEBUG_SYM_DIR/"
echo "[freebsd-module-build] mirrored unstripped .ko into $DEBUG_SYM_DIR"
