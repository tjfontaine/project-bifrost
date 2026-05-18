#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# stage-smolvm.sh — thin alias for `cargo build --release -p smolvm`.
#
# HISTORY: this script used to do the codesign+entitlement re-sign
# dance manually because every `cargo build --release` produces a
# binary with an adhoc *linker-signed* signature that has NO
# entitlements. Without `com.apple.security.hypervisor`, HVF's
# `hv_vm_create` returns HV_DENIED, surfacing as the opaque
# `krun_start_enter -22` (libc EINVAL).
#
# As of Phase F (atomic build pipeline), the codesign+entitlement
# step is folded into `third_party/smolvm/build.rs` so it runs
# automatically on every cargo build. The full transactional
# pipeline (kernel → libkrunfw → cargo → codesign + validate) lives
# at `tools/rebuild-driver`.
#
# This script is preserved as a documented entrypoint for users who
# don't want to remember the cargo invocation. It is now equivalent
# to running `cargo build --release -p smolvm`.
#
# Usage:
#   host/runtime/stage-smolvm.sh
#
# Lives at host/runtime/ so the project NOPASSWD sudoers entry
# (host/*/*) covers any sudo invocation. sudo isn't required for
# the cargo invocation; the wrapper is sudo-compatible so callers
# already in a sudo'd context can invoke it transparently.
#
# See also:
#   tools/rebuild-driver           — full atomic rebuild pipeline
#   docs/troubleshooting-rebuilds.md — known failure modes

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$ROOT/third_party/smolvm"
BIN="$SMOLVM_DIR/target/release/smolvm"
ENTITLEMENTS="$SMOLVM_DIR/smolvm.entitlements"

cd "$SMOLVM_DIR"
if [ -z "${LIBKRUN_BUNDLE:-}" ]; then
    export LIBKRUN_BUNDLE="$SMOLVM_DIR/lib"
fi
cargo build --release -p smolvm

# Defensive validate: build.rs should have re-signed with the
# hypervisor entitlement, but verify so we fail loud if something
# went wrong rather than at first VM boot.
if [ -f "$BIN" ]; then
    if ! codesign -d --entitlements - "$BIN" 2>&1 | grep -q "com.apple.security.hypervisor"; then
        echo "[stage-smolvm] hypervisor entitlement absent on $BIN" >&2
        echo "[stage-smolvm] re-signing manually..." >&2
        codesign --force --sign - --entitlements "$ENTITLEMENTS" "$BIN"
        if ! codesign -d --entitlements - "$BIN" 2>&1 | grep -q "com.apple.security.hypervisor"; then
            echo "[stage-smolvm] verify failed: hypervisor entitlement still missing" >&2
            echo "[stage-smolvm] check $ENTITLEMENTS plist syntax" >&2
            exit 1
        fi
    fi
    echo "[stage-smolvm] $BIN ($(wc -c <"$BIN" | tr -d ' ') bytes, hypervisor entitlement present)"
else
    echo "[stage-smolvm] $BIN not produced; check cargo output above" >&2
    exit 1
fi
