#!/bin/sh
# scripts/cross-kernel-x2-demo.sh — clean + rebuild + run the cross-kernel
# demo in one shot.  Lives at scripts/cross-kernel-x2-demo.sh; runs via
# `sudo -n` under the project's NOPASSWD wildcard.
#
# Use this instead of pasting the same cleanup + rebuild + launch
# incantation by hand.
set -eu
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

sudo -n host/runtime/cleanup.sh >/dev/null 2>&1 || true
rm -rf ~/Library/Caches/smolvm/vms/* 2>/dev/null || true
rm -f /tmp/bifrost-orch-* /tmp/bifrost-x2-orch.log 2>/dev/null || true

# Quick rebuild only if source newer than staged bin.
if find host/bifrost/src host/bifrost-wire/src -name '*.rs' -newer host/runtime/bifrost \
    -print -quit 2>/dev/null | grep -q .; then
    echo "[demo] rebuilding bifrost"
    cargo build --manifest-path host/bifrost/Cargo.toml --release --bin bifrost
    cp -p host/bifrost/target/release/bifrost host/runtime/bifrost
    codesign --force --sign - host/runtime/bifrost >/dev/null
fi

echo "[demo] running BIFROST_LIVE=1 demo"
BIFROST_LIVE=1 timeout 480 examples/cross-kernel-linux-fbsd-x2/run.sh
