#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# stage-libkrun.sh — copy a freshly-built libkrun.dylib into
# third_party/smolvm/lib/ and re-codesign it.
#
# Background: Cargo's linker-signed Mach-O signature on macOS isn't
# accepted by dyld when DYLD_LIBRARY_PATH points at the artifact —
# loading the dylib via smolvm exits with SIGKILL (Code Signature
# Invalid) before main() even runs (EXC_BAD_ACCESS in
# mach_o::Universal::isUniversal during dyld setup).
#
# The cure is `codesign --force -s -` which replaces the linker
# signature with an adhoc one dyld accepts. We did this manually
# every time we rebuilt libkrun this session — encode it into the
# build pipeline so future rebuilds Just Work.
#
# Usage:
#   sudo -n host/runtime/stage-libkrun.sh
#
# Lives at host/runtime/ so the project NOPASSWD sudoers entry
# (host/*/*) covers sudo invocation. sudo isn't strictly required
# for cp+codesign on a user-owned tree, but the wrapper is sudo-
# compatible so build scripts that already run under sudo can
# invoke it transparently.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/third_party/smolvm/libkrun/target/release/libkrun.dylib"
DST_DIR="$ROOT/third_party/smolvm/lib"
DST="$DST_DIR/libkrun.dylib"

if [ ! -f "$SRC" ]; then
    echo "[stage-libkrun] $SRC not found" >&2
    echo "[stage-libkrun] build first:" >&2
    echo "  cd third_party/smolvm/libkrun" >&2
    echo "  KRUN_INIT_BINARY_PATH=\$(find target/release/build/krun-devices-*/out/init | head -1) \\" >&2
    echo "      RUSTFLAGS=\"-L $ROOT/third_party/smolvm/lib\" \\" >&2
    echo "      DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/usr/lib \\" >&2
    echo "      LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib \\" >&2
    echo "      cargo build --release -p libkrun --features blk,gpu" >&2
    exit 1
fi

mkdir -p "$DST_DIR"
# rm + cp -p (not just cp) because in-place overwrite of a loaded
# dylib in another process can race with codesign's signature
# rewrite — easier to atomically replace.
rm -f "$DST"
cp -p "$SRC" "$DST"

# Re-sign with adhoc; --force replaces Cargo's linker signature.
codesign --force -s - "$DST"
codesign --verify --verbose "$DST" >/dev/null 2>&1 || {
    echo "[stage-libkrun] codesign verify failed" >&2
    exit 1
}

echo "[stage-libkrun] $DST ($(wc -c <"$DST" | tr -d ' ') bytes, adhoc-signed)"
