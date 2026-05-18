#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# diagnose.sh — single-shot health check for a bifrost install.
#
# The contract: when the demo doesn't work, the operator runs
# this script and pastes its output instead of debugging by hand.
# Every check exits 0 even on failure so the diagnostic captures
# the full picture in one run.  The summary at the bottom names
# the bucket each failure falls into so the fix is obvious.

set -u

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

ok=0
warn=0
fail=0

pass() { printf '  \033[32mOK\033[0m   %s\n' "$*"; ok=$((ok + 1)); }
warning() { printf '  \033[33mWARN\033[0m %s\n' "$*"; warn=$((warn + 1)); }
failure() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }
section() { printf '\n[diagnose] %s\n' "$*"; }

# ---------------------------------------------------------------
# Host platform.
# ---------------------------------------------------------------
section "host platform"
case "$(uname -s)" in
    Darwin) pass "macOS host ($(sw_vers -productVersion 2>/dev/null || echo unknown))" ;;
    *) failure "non-macOS host: $(uname -s)" ;;
esac
case "$(uname -m)" in
    arm64|aarch64) pass "Apple Silicon ($(uname -m))" ;;
    *) failure "non-aarch64: $(uname -m)" ;;
esac

# ---------------------------------------------------------------
# Toolchain.
# ---------------------------------------------------------------
section "toolchain"
for tool in brew cargo rustc git codesign curl xz qemu-img; do
    if command -v "$tool" >/dev/null 2>&1; then
        pass "$tool ($(command -v "$tool"))"
    else
        failure "$tool not on PATH"
    fi
done

# ---------------------------------------------------------------
# Custom QEMU.
# ---------------------------------------------------------------
section "custom QEMU"
QEMU_BIN="${QEMU:-/private/tmp/qemu-11.0.0/build/qemu-system-aarch64}"
if [ -x "$QEMU_BIN" ]; then
    pass "QEMU present at $QEMU_BIN"
    # Verify vhost-user-test-device-pci is compiled in.
    if "$QEMU_BIN" -device help 2>&1 | grep -q vhost-user-test-device-pci; then
        pass "QEMU has vhost-user-test-device-pci"
    else
        failure "QEMU built without vhost-user-test-device-pci"
    fi
else
    failure "custom QEMU missing at $QEMU_BIN"
fi

# ---------------------------------------------------------------
# Built binaries.
# ---------------------------------------------------------------
section "staged binaries"
for bin in bifrost conduit-backend conduit_shm_diag smolvm-launch.sh qemu-launch-freebsd.sh; do
    p="$PROJECT_ROOT/host/runtime/$bin"
    if [ -x "$p" ]; then
        pass "host/runtime/$bin"
    else
        failure "host/runtime/$bin missing or not executable"
    fi
done
SMOLVM_BIN="$PROJECT_ROOT/third_party/smolvm/target/release/smolvm"
if [ -x "$SMOLVM_BIN" ]; then
    pass "smolvm binary: $SMOLVM_BIN"
    if codesign -d --entitlements - "$SMOLVM_BIN" 2>&1 | grep -q "com.apple.security.hypervisor"; then
        pass "smolvm has hypervisor entitlement"
    else
        failure "smolvm missing hypervisor entitlement — re-run host/runtime/stage-smolvm.sh"
    fi
else
    failure "smolvm binary missing — run scripts/first-run.sh"
fi

# ---------------------------------------------------------------
# Staged dylibs.
# ---------------------------------------------------------------
section "dylibs"
for lib in libkrun.dylib libkrunfw.5.dylib; do
    p="$PROJECT_ROOT/third_party/smolvm/lib/$lib"
    if [ -f "$p" ]; then
        if codesign --verify "$p" >/dev/null 2>&1; then
            pass "$lib (adhoc-signed)"
        else
            failure "$lib codesign verify failed — run host/runtime/stage-$([ "$lib" = libkrun.dylib ] && echo libkrun || echo libkrunfw).sh"
        fi
    else
        failure "$lib not staged at $p"
    fi
done

# ---------------------------------------------------------------
# FreeBSD QCOW2 + debug symbols.
# ---------------------------------------------------------------
section "FreeBSD artifacts"
FBSD_QCOW2="$(ls "$PROJECT_ROOT/artifacts/freebsd"/FreeBSD-*-arm64-aarch64.qcow2 2>/dev/null | head -1)"
if [ -n "$FBSD_QCOW2" ] && [ -s "$FBSD_QCOW2" ]; then
    pass "FreeBSD QCOW2: $FBSD_QCOW2 ($(du -h "$FBSD_QCOW2" | awk '{print $1}'))"
else
    failure "no FreeBSD QCOW2 under artifacts/freebsd/"
fi
if [ -s "$PROJECT_ROOT/artifacts/freebsd/debug-symbols/kernel" ]; then
    pass "FreeBSD debug-symbols/kernel present"
else
    warning "FreeBSD debug-symbols/kernel missing — run scripts/fetch-freebsd-debug-symbols.sh"
fi
if [ -d "$PROJECT_ROOT/artifacts/freebsd/module-disk/boot/kernel" ]; then
    n_modules="$(find "$PROJECT_ROOT/artifacts/freebsd/module-disk/boot/kernel" -name '*.ko' | wc -l | tr -d ' ')"
    pass "FreeBSD module disk: $n_modules kernel modules staged"
else
    failure "FreeBSD module disk missing — run guest/freebsd-bifrost/stage-module-disk.sh"
fi

# ---------------------------------------------------------------
# Patches in sync.
# ---------------------------------------------------------------
section "patch sync"
if "$PROJECT_ROOT/scripts/verify-patches.sh" >/tmp/diagnose-verify-patches.log 2>&1; then
    pass "vendored patches match canonical bifrost sources"
else
    failure "verify-patches.sh failed (see /tmp/diagnose-verify-patches.log)"
fi

# ---------------------------------------------------------------
# Sudoers.
# ---------------------------------------------------------------
section "sudoers"
ME="$(id -un)"
WANT_PATTERN="${PROJECT_ROOT}/*/*/*"
if sudo -n -l 2>/dev/null | grep -q -F "$WANT_PATTERN"; then
    pass "NOPASSWD coverage for $WANT_PATTERN"
else
    failure "no NOPASSWD coverage for $WANT_PATTERN"
    echo "       install: ${ME} ALL=(root) NOPASSWD: $WANT_PATTERN"
fi
if sudo -n true 2>/dev/null; then
    pass "sudo -n true succeeded (cached creds or full ALL=NOPASSWD)"
else
    warning "sudo -n true requires a password — only the bifrost path is NOPASSWD-covered"
fi

# ---------------------------------------------------------------
# Live SHM probe — any conduit-data SHM segments left over from a
# crashed previous run?
# ---------------------------------------------------------------
section "stale conduit state"
LEAKED="$(ls /tmp/conduit-*.sock 2>/dev/null || true)"
if [ -n "$LEAKED" ]; then
    warning "leaked conduit sockets from a previous run:"
    echo "$LEAKED" | sed 's/^/         /'
    echo "         remove with: rm -f /tmp/conduit-*.sock"
else
    pass "no leaked /tmp/conduit-*.sock files"
fi
LEAKED_PIDS="$(ls /tmp/bifrost-*-backend.pid /tmp/bifrost-orch-*-backend.pid 2>/dev/null || true)"
if [ -n "$LEAKED_PIDS" ]; then
    warning "stale launcher pid files:"
    echo "$LEAKED_PIDS" | sed 's/^/         /'
    echo "         clean with: rm -f /tmp/bifrost-*-backend.pid /tmp/bifrost-orch-*"
else
    pass "no stale launcher pid files"
fi

# ---------------------------------------------------------------
# macOS host dtrace — third-kernel arm.
# ---------------------------------------------------------------
section "macOS host dtrace"
DTRACE_BIN="/usr/sbin/dtrace"
if [ -x "$DTRACE_BIN" ]; then
    pass "dtrace present at $DTRACE_BIN"
else
    failure "dtrace missing — macos-host target won't work (System Integrity Protection or removed binary)"
fi
# The cross-kernel demo spawns `sudo -n /usr/sbin/dtrace …` so the operator needs
# NOPASSWD coverage for that exact path.  $WANT_PATTERN above
# matches anything under project root; we additionally check for
# explicit /usr/sbin/dtrace coverage so unprivileged sessions can
# drive macos-host without a password prompt mid-run.
if sudo -n -l 2>/dev/null | grep -Eq "(/usr/sbin/dtrace|/usr/sbin/\*|ALL\s*$|NOPASSWD:\s*ALL)"; then
    pass "NOPASSWD coverage for /usr/sbin/dtrace (or ALL)"
else
    warning "no NOPASSWD coverage for /usr/sbin/dtrace — macos-host target will prompt"
    echo "       install: ${ME} ALL=(root) NOPASSWD: /usr/sbin/dtrace"
fi

# ---------------------------------------------------------------
# Cross-kernel demo dry-run — the canonical end-to-end gate.
# ---------------------------------------------------------------
section "demo dry-run"
if [ -x "$PROJECT_ROOT/examples/cross-kernel-linux-fbsd-x2/run.sh" ]; then
    if "$PROJECT_ROOT/examples/cross-kernel-linux-fbsd-x2/run.sh" >/tmp/diagnose-demo-dryrun.log 2>&1; then
        pass "cross-kernel-linux-fbsd-x2 dry-run passes"
    else
        failure "cross-kernel-linux-fbsd-x2 dry-run failed (see /tmp/diagnose-demo-dryrun.log)"
        sed 's/^/         /' /tmp/diagnose-demo-dryrun.log | tail -20
    fi
else
    failure "examples/cross-kernel-linux-fbsd-x2/run.sh missing or not executable"
fi
if [ -x "$PROJECT_ROOT/examples/three-kernels/run.sh" ]; then
    if "$PROJECT_ROOT/examples/three-kernels/run.sh" >/tmp/diagnose-3k-dryrun.log 2>&1; then
        pass "three-kernels dry-run passes"
    else
        failure "three-kernels dry-run failed (see /tmp/diagnose-3k-dryrun.log)"
        sed 's/^/         /' /tmp/diagnose-3k-dryrun.log | tail -20
    fi
else
    failure "examples/three-kernels/run.sh missing or not executable"
fi

# ---------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------
section "summary"
printf '  %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
if [ "$fail" -gt 0 ]; then
    echo "  fix the FAIL items above (each line names the script that re-stages it)"
    echo "  then re-run scripts/diagnose.sh"
    exit 1
fi
if [ "$warn" -gt 0 ]; then
    echo "  WARN items won't block the demo but may slow it down or hide failure modes"
fi
echo "  install looks healthy — try BIFROST_LIVE=1 examples/cross-kernel-linux-fbsd-x2/run.sh"
exit 0
