#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# stage-conduit-backend.sh — copy a freshly-built vhost-user
# conduit backend into host/runtime/ and make it executable by the
# macOS loader.
#
# Build:
#   cargo build --release --manifest-path host/conduit-backend/Cargo.toml
#
# Stage:
#   host/runtime/stage-conduit-backend.sh
#
# Cargo's linker signature can be killed by macOS after copying into
# host/runtime/. Replace it with an explicit ad-hoc signature so
# qemu-launch-freebsd.sh and smolvm-launch.sh can execute the staged
# backend reliably.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/host/conduit-backend/target/release/conduit-backend"
DST="$ROOT/host/runtime/conduit-backend"

if [ ! -f "$SRC" ]; then
    echo "[stage-conduit-backend] $SRC not found" >&2
    echo "[stage-conduit-backend] build first:" >&2
    echo "  cargo build --release --manifest-path host/conduit-backend/Cargo.toml" >&2
    exit 1
fi

rm -f "$DST"
cp -p "$SRC" "$DST"
chmod 0755 "$DST"

if [ "$(uname -s)" = "Darwin" ]; then
    codesign --force --sign - "$DST" >/dev/null
fi

"$DST" --help >/dev/null
echo "[stage-conduit-backend] $DST ($(wc -c <"$DST" | tr -d ' ') bytes, src=${SRC#$ROOT/})"
