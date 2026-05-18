#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# stage-libkrunfw.sh — copy a freshly-built libkrunfw.5.dylib into
# third_party/smolvm/lib/ and re-codesign it. Companion to
# stage-libkrun.sh; same rationale (Cargo/cc linker signature
# rejected by dyld under DYLD_LIBRARY_PATH on macOS).
#
# Usage:
#   sudo -n host/runtime/stage-libkrunfw.sh

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/third_party/smolvm/libkrunfw/libkrunfw.5.dylib"
DST_DIR="$ROOT/third_party/smolvm/lib"
DST="$DST_DIR/libkrunfw.5.dylib"

if [ ! -f "$SRC" ]; then
    echo "[stage-libkrunfw] $SRC not found" >&2
    echo "[stage-libkrunfw] build first:" >&2
    echo "  cd third_party/smolvm/libkrunfw" >&2
    echo "  ./build_on_krunvm_fedora.sh    # builds kernel.c via krunvm Fedora" >&2
    echo "  make                           # builds the .dylib on macOS" >&2
    exit 1
fi

mkdir -p "$DST_DIR"
rm -f "$DST"
cp -p "$SRC" "$DST"

codesign --force -s - "$DST"
codesign --verify --verbose "$DST" >/dev/null 2>&1 || {
    echo "[stage-libkrunfw] codesign verify failed" >&2
    exit 1
}

echo "[stage-libkrunfw] $DST ($(wc -c <"$DST" | tr -d ' ') bytes, adhoc-signed)"
