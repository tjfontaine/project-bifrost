#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# stage-agent.sh — copy a freshly cross-compiled smolvm-agent
# Linux binary into third_party/smolvm/target/agent-rootfs/.
# Companion to stage-libkrun.sh / stage-libkrunfw.sh; same
# motivation (uniform host/runtime/* staging surface).
#
# Why this is needed: after rebasing smolvm onto a new upstream,
# the bundled agent-rootfs/usr/local/bin/smolvm-agent encodes the
# *old* agent's vsock/protocol expectations and will silently
# fail to negotiate with the new smolvm CLI (symptom: agent boots,
# but `machine run -d` returns "agent returned exit code 1" almost
# immediately, and ~/Library/Caches/smolvm/vms/*/agent-console.log
# shows the agent's "smolvm-agent started, version=X" log line at
# an unexpected version). Re-stage after every upstream bump.
#
# Build (run from third_party/smolvm/):
#   cargo make build-agent          # cross-compiles for aarch64-musl via Docker
#
# Stage:
#   host/runtime/stage-agent.sh     # no sudo required
#
# Lives at host/runtime/ so the project NOPASSWD sudoers entry
# (host/*/*) covers `sudo -n host/runtime/stage-agent.sh` for
# callers that already run under sudo. sudo itself is not needed
# for a user-owned target tree.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$ROOT/third_party/smolvm"

# `cargo make build-agent` writes to release-small first (aarch64
# host build path); the linux-musl cross target is the fallback if
# the cross-toolchain ran instead. Prefer the most recently built.
SRC=""
for cand in \
    "$SMOLVM_DIR/target/release-small/smolvm-agent" \
    "$SMOLVM_DIR/target/aarch64-unknown-linux-musl/release/smolvm-agent" \
    "$SMOLVM_DIR/target/x86_64-unknown-linux-musl/release/smolvm-agent"
do
    if [ -f "$cand" ]; then
        if [ -z "$SRC" ] || [ "$cand" -nt "$SRC" ]; then
            SRC="$cand"
        fi
    fi
done

if [ -z "$SRC" ]; then
    echo "[stage-agent] no smolvm-agent binary found" >&2
    echo "[stage-agent] build first:" >&2
    echo "  cd $SMOLVM_DIR && cargo make build-agent" >&2
    exit 1
fi

DST_DIR="$SMOLVM_DIR/target/agent-rootfs/usr/local/bin"
DST="$DST_DIR/smolvm-agent"

if [ ! -d "$DST_DIR" ]; then
    echo "[stage-agent] agent rootfs target directory not found: $DST_DIR" >&2
    echo "[stage-agent] build the rootfs first:" >&2
    echo "  cd $SMOLVM_DIR && ./scripts/build-agent-rootfs.sh" >&2
    exit 1
fi

# rm + cp -p so an in-progress smolvm boot can't see a half-written
# binary; the next VM boot picks up the new agent atomically.
rm -f "$DST"
cp -p "$SRC" "$DST"
chmod 0755 "$DST"

echo "[stage-agent] $DST ($(wc -c <"$DST" | tr -d ' ') bytes, src=${SRC#$ROOT/})"
