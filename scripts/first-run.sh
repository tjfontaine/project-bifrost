#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# first-run.sh — single-shot bring-up for a clean M-series Mac
# checkout.  Idempotent; safe to re-run.  Walks the operator from
# `git clone` to a green cross-kernel-linux-fbsd-x2 demo without
# them needing to read a README more than once.
#
# What this script DOES NOT do:
#   - Install macOS itself or Xcode CLT.  Pre-req gates fail loud.
#   - Install Homebrew.  Pre-req gate fails loud.
#   - Modify your sudoers automatically.  Prints the snippet for
#     the operator to install with `visudo -f /etc/sudoers.d/bifrost`.
#
# Each step is independent so a partial install just resumes from
# the first missing artifact.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

log() { printf '[first-run] %s\n' "$*"; }
warn() { printf '[first-run] WARN: %s\n' "$*" >&2; }
die() { printf '[first-run] FATAL: %s\n' "$*" >&2; exit 1; }
section() { printf '\n[first-run] ==== %s ====\n' "$*"; }

# ---------------------------------------------------------------
# Step 0 — host gate.  Refuse non-macOS aarch64 hosts up front
# rather than failing deep in the demo.
# ---------------------------------------------------------------
section "step 0: host platform"
case "$(uname -s)" in
    Darwin) ;;
    *) die "first-run.sh only supports macOS aarch64. detected: $(uname -s)" ;;
esac
case "$(uname -m)" in
    arm64|aarch64) ;;
    *) die "first-run.sh only supports Apple Silicon. detected: $(uname -m)" ;;
esac
MACOS_MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
if [ "$MACOS_MAJOR" -lt 14 ]; then
    die "macOS 14+ required (detected $(sw_vers -productVersion))"
fi
log "host: macOS $(sw_vers -productVersion) on $(uname -m)"

# ---------------------------------------------------------------
# Step 1 — toolchain gate.  Anything we can't auto-install we
# name explicitly with a paste-ready brew command.
# ---------------------------------------------------------------
section "step 1: toolchain"
need() { command -v "$1" >/dev/null 2>&1 || missing="${missing:-} $1"; }
missing=""
need brew
need cargo
need rustc
need git
need codesign
need curl
if [ -n "$missing" ]; then
    die "missing tools:$missing
install via: xcode-select --install (codesign/git) + https://brew.sh (brew + cargo via rustup)"
fi
log "core toolchain present"

# Homebrew packages — bmake/aarch64-elf-gdb/llvm/qemu are needed
# by the FreeBSD cross-build path and qemu-img.
BREW_PKGS="bmake aarch64-elf-gdb llvm qemu"
missing_brew=""
for pkg in $BREW_PKGS; do
    brew list --formula --quiet "$pkg" >/dev/null 2>&1 || missing_brew="$missing_brew $pkg"
done
if [ -n "$missing_brew" ]; then
    warn "homebrew packages missing:$missing_brew"
    log "  install with: brew install$missing_brew"
    if [ "${FIRST_RUN_AUTO_INSTALL:-0}" = "1" ]; then
        # shellcheck disable=SC2086
        brew install $missing_brew
    else
        die "install the missing packages, then re-run first-run.sh (or set FIRST_RUN_AUTO_INSTALL=1)"
    fi
else
    log "homebrew packages present ($BREW_PKGS)"
fi

# ---------------------------------------------------------------
# Step 2 — custom QEMU.  The launcher hardcodes a build at
# /private/tmp/qemu-11.0.0/build/qemu-system-aarch64.  We can't
# reproduce it from scratch in a single first-run today, so we
# fail loud with build instructions.  (Tracked as a follow-up:
# scripts/build-qemu.sh that lands the verified revision +
# configure flags.)
# ---------------------------------------------------------------
section "step 2: custom QEMU"
QEMU_BIN="${QEMU:-/private/tmp/qemu-11.0.0/build/qemu-system-aarch64}"
if [ ! -x "$QEMU_BIN" ]; then
    cat >&2 <<EOF
[first-run] FATAL: custom QEMU not found at $QEMU_BIN

  The FreeBSD launcher needs a QEMU build with vhost-user-test-device-pci
  and memory-backend-shm enabled.  Until scripts/build-qemu.sh ships,
  build it by hand:

    curl -L -o /tmp/qemu-11.0.0.tar.xz https://download.qemu.org/qemu-11.0.0.tar.xz
    tar -C /private/tmp -xf /tmp/qemu-11.0.0.tar.xz
    cd /private/tmp/qemu-11.0.0
    ./configure --target-list=aarch64-softmmu --enable-hvf \\
                --enable-vhost-user --enable-vhost-user-test-device
    make -j$(sysctl -n hw.ncpu)

  Then re-run first-run.sh.  Override the path with QEMU=/path/to/qemu-system-aarch64.
EOF
    die "QEMU prerequisite missing"
fi
log "custom QEMU present at $QEMU_BIN"
export QEMU

# ---------------------------------------------------------------
# Step 3 — submodules.  The smolvm and FreeBSD trees are nested
# repos under third_party/; pull them so subsequent steps have
# source to build.
# ---------------------------------------------------------------
section "step 3: submodules"
git submodule update --init --recursive
log "submodules synced"

# ---------------------------------------------------------------
# Step 4 — patch hygiene.  Confirm the vendored kernel patches
# match the bifrost canonical sources so a stale rebase doesn't
# silently ship the wrong kernel.
# ---------------------------------------------------------------
section "step 4: patch verification"
"$PROJECT_ROOT/scripts/verify-patches.sh"

# ---------------------------------------------------------------
# Step 5 — bifrost CLI.  Builds the user-facing binary that
# orchestrates everything else.  cargo build is idempotent.
# ---------------------------------------------------------------
section "step 5: build bifrost CLI"
cargo build --manifest-path host/bifrost/Cargo.toml --release --bin bifrost
cp -p "$PROJECT_ROOT/host/bifrost/target/release/bifrost" "$PROJECT_ROOT/host/runtime/bifrost"
codesign --force --sign - "$PROJECT_ROOT/host/runtime/bifrost"
log "host/runtime/bifrost staged + adhoc-signed"

# ---------------------------------------------------------------
# Step 6 — conduit-backend.  Pre-builds the vhost-user backend
# binary smolvm-launch.sh + qemu-launch-freebsd.sh execute.
# ---------------------------------------------------------------
section "step 6: build + stage conduit-backend"
cargo build --release --manifest-path host/conduit-backend/Cargo.toml
"$PROJECT_ROOT/host/runtime/stage-conduit-backend.sh"

# ---------------------------------------------------------------
# Step 7 — smolvm.  build.rs re-applies the hypervisor entitlement
# after each cargo build (memory: cargo build strips smolvm's
# entitlements; stage-smolvm.sh has a defensive re-sign).
# ---------------------------------------------------------------
section "step 7: build smolvm + libkrun + libkrunfw"
# libkrunfw + libkrun must exist as staged dylibs before smolvm
# can link.  Build them only if the staged artifact is absent
# (the upstream builds take 5–10 minutes each).
if [ ! -f "$PROJECT_ROOT/third_party/smolvm/lib/libkrunfw.5.dylib" ]; then
    log "building libkrunfw (one-time, ~5 min)"
    ( cd "$PROJECT_ROOT/third_party/smolvm/libkrunfw" && ./build_on_krunvm_fedora.sh && make )
    "$PROJECT_ROOT/host/runtime/stage-libkrunfw.sh"
else
    log "libkrunfw.5.dylib already staged"
fi
if [ ! -f "$PROJECT_ROOT/third_party/smolvm/lib/libkrun.dylib" ]; then
    log "building libkrun (one-time, ~5 min)"
    ( cd "$PROJECT_ROOT/third_party/smolvm/libkrun" && cargo build --release )
    "$PROJECT_ROOT/host/runtime/stage-libkrun.sh"
else
    log "libkrun.dylib already staged"
fi
"$PROJECT_ROOT/host/runtime/stage-smolvm.sh"

# ---------------------------------------------------------------
# Step 8 — FreeBSD QCOW2 + debug symbols.  The launcher
# auto-downloads the QCOW2 on first invocation; pre-warm it so
# the operator's first demo run doesn't silently wait on a
# ~600 MB cold cache.
# ---------------------------------------------------------------
section "step 8: FreeBSD QCOW2 + debug symbols"
FBSD_RELEASE="${FREEBSD_RELEASE:-14.3-RELEASE}"
FBSD_QCOW2="$PROJECT_ROOT/artifacts/freebsd/FreeBSD-${FBSD_RELEASE}-arm64-aarch64.qcow2"
if [ ! -s "$FBSD_QCOW2" ]; then
    log "pre-fetching FreeBSD ${FBSD_RELEASE} aarch64 QCOW2 (~600 MB; one-time)"
    mkdir -p "$PROJECT_ROOT/artifacts/freebsd"
    URL="https://download.freebsd.org/releases/VM-IMAGES/${FBSD_RELEASE}/aarch64/Latest/FreeBSD-${FBSD_RELEASE}-arm64-aarch64.qcow2.xz"
    XZ="$PROJECT_ROOT/artifacts/freebsd/$(basename "$URL")"
    curl -fL --progress-bar -o "$XZ.part" "$URL"
    mv "$XZ.part" "$XZ"
    log "decompressing $(basename "$XZ")"
    xz -dk "$XZ"
    rm -f "$XZ"
else
    log "FreeBSD QCOW2 already cached at $FBSD_QCOW2"
fi
if [ ! -s "$PROJECT_ROOT/artifacts/freebsd/debug-symbols/kernel" ]; then
    log "fetching FreeBSD debug symbols"
    "$PROJECT_ROOT/scripts/fetch-freebsd-debug-symbols.sh"
else
    log "FreeBSD debug symbols already present"
fi

# ---------------------------------------------------------------
# Step 9 — FreeBSD module disk.  qemu-launch-freebsd.sh expects
# /opt/homebrew/share/qemu/edk2-aarch64-code.fd; install it via
# `brew install qemu` if missing.  Also stage the bifrost FreeBSD
# kernel modules onto the module disk so the EFI preload picks
# them up.
# ---------------------------------------------------------------
section "step 9: FreeBSD module disk"
EDK2_CODE="${FREEBSD_EDK2_CODE:-/opt/homebrew/share/qemu/edk2-aarch64-code.fd}"
if [ ! -f "$EDK2_CODE" ]; then
    die "EDK2 firmware missing at $EDK2_CODE — reinstall homebrew qemu (brew reinstall qemu)"
fi
MODULES_DIR="$PROJECT_ROOT/artifacts/freebsd/module-disk"
if [ ! -d "$MODULES_DIR/boot/kernel" ]; then
    if [ -x "$PROJECT_ROOT/guest/freebsd-bifrost/stage-module-disk.sh" ]; then
        log "staging FreeBSD bifrost kernel modules into $MODULES_DIR"
        "$PROJECT_ROOT/guest/freebsd-bifrost/stage-module-disk.sh"
    else
        warn "guest/freebsd-bifrost/stage-module-disk.sh not present — the FreeBSD-side"
        warn "  bifrost_conduit.ko + provider modules must be built by hand for the demo to attach."
    fi
else
    log "module disk already staged at $MODULES_DIR"
fi

# ---------------------------------------------------------------
# Step 10 — sudoers detection.  bifrost runs under `sudo -n` so
# launch + drain paths can open the libkrun device and bind
# vhost-user sockets without prompting.  Detect missing
# NOPASSWD coverage and print the exact snippet to install.
# ---------------------------------------------------------------
section "step 10: sudoers"
ME="$(id -un)"
SUDOERS_SNIPPET="${ME} ALL=(root) NOPASSWD: ${PROJECT_ROOT}/*/*/*"
if sudo -n -l 2>/dev/null | grep -q -F "${PROJECT_ROOT}/*/*/*"; then
    log "NOPASSWD coverage for ${PROJECT_ROOT}/*/*/* is active"
else
    cat <<EOF
[first-run] WARN: no NOPASSWD sudoers entry covers ${PROJECT_ROOT}/*/*/*

  Install with:
      sudo visudo -f /etc/sudoers.d/bifrost
  and add the line:
      $SUDOERS_SNIPPET

  Without this entry, every sudo invocation during the demo will
  prompt for a password and the launcher's timing windows will
  blow past their bounds.  Re-run scripts/diagnose.sh once the
  entry is installed.
EOF
fi

# ---------------------------------------------------------------
# Step 11 — final validation: dry-run the cross-kernel demo so
# the operator sees a green plan + routing pass before paying
# the live-boot cost.
# ---------------------------------------------------------------
section "step 11: validate"
"$PROJECT_ROOT/examples/cross-kernel-linux-fbsd-x2/run.sh"

cat <<EOF

[first-run] all install steps complete.

Next step — boot the demo end-to-end (takes ~90 s on first run):

    BIFROST_LIVE=1 examples/cross-kernel-linux-fbsd-x2/run.sh

If anything fails, capture diagnostics with:

    scripts/diagnose.sh
EOF
