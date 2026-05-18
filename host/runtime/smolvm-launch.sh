#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# smolvm-launch.sh — launcher that orchestrates the
# vhost-user conduit-backend alongside smolvm.
#
# WHY THIS EXISTS
# ---------------
#
# An earlier design ran the conduit as an in-process libkrun
# device.  The conduit protocol now lives in a separate
# `conduit-backend` binary that libkrun connects to over a
# vhost-user UNIX socket
# (gated on the `vhost-user` Cargo feature in libkrun). The two
# processes have a startup ordering requirement:
#
#   1. `conduit-backend` must be running and bound to the socket
#      *before* libkrun's vhost-user-device frontend tries to
#      connect.
#   2. The socket path must be agreed between the two.
#   3. On clean shutdown, the backend must outlive the VM so the
#      shutdown ctrl-payloads have somewhere to land.
#
# This script handles that orchestration. It is a thin alias for:
#
#   conduit-backend --socket $SOCK &
#   wait-for-socket $SOCK
#   smolvm machine run ... --vhost-user-device=$SOCK -- <cmd>
#   (on smolvm exit: kill conduit-backend, unlink socket)
#
# USAGE
#
#   host/runtime/smolvm-launch.sh machine run <smolvm-args...>
#
# All positional args are forwarded to `smolvm` after the
# `--vhost-user-device=<path>` flag is injected before any
# command separator (`--`). The script
# requires `conduit-backend` and `smolvm` to be on PATH (the
# `host/runtime/` directory is the canonical location).
#
# ENVIRONMENT
#
#   CONDUIT_SOCK         optional override for the socket path.
#                        Defaults to /tmp/conduit-<pid>.sock.
#   CONDUIT_LOG          optional path for backend stdout/stderr.
#                        Defaults to /tmp/conduit-backend.log.
#   CONDUIT_WAIT_MS      bound on the socket-readiness wait.
#                        Defaults to 5000.
#   CONDUIT_DATA_SHM_NAME
#                        optional POSIX SHM name shared by backend
#                        and libkrun. Defaults to /conduit-data-<pid>.
#
# Lives at host/runtime/ so the project NOPASSWD sudoers entry
# (host/*/*) covers callers already in a sudo context.

set -euo pipefail

# Resolve smolvm binary relative to this script so callers don't
# need to put smolvm on PATH. Demos typically set DYLD_LIBRARY_PATH
# but not PATH; honor SMOLVM_BIN override for non-standard layouts.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SMOLVM_BIN="${SMOLVM_BIN:-$PROJECT_ROOT/third_party/smolvm/target/release/smolvm}"
CONDUIT_BACKEND_BIN="${CONDUIT_BACKEND_BIN:-$SCRIPT_DIR/conduit-backend}"

# Point smolvm at the in-tree agent-rootfs so a fresh checkout
# doesn't fail with "agent rootfs not found:
# ~/Library/Application Support/smolvm/agent-rootfs".  The in-tree
# directory is populated by host/runtime/stage-agent.sh after
# `cargo make build-agent` in third_party/smolvm/.  User-provided
# SMOLVM_AGENT_ROOTFS overrides — handy if an operator has staged
# a custom rootfs in the platform data dir.
if [ -z "${SMOLVM_AGENT_ROOTFS:-}" ] && [ -d "$PROJECT_ROOT/third_party/smolvm/target/agent-rootfs" ]; then
    export SMOLVM_AGENT_ROOTFS="$PROJECT_ROOT/third_party/smolvm/target/agent-rootfs"
fi

# Drop-in shim for `smolvm` that injects --vhost-user-device for
# `machine run` only. For all other smolvm subcommands (machine
# exec/stop/status/delete/etc.) pass through directly so callers
# don't accidentally spin up a conduit-backend per invocation.
NEEDS_BACKEND=0
if [ "${1:-}" = "machine" ] && [ "${2:-}" = "run" ]; then
    # If the caller already wired up --vhost-user-device, leave it
    # alone; the explicit socket wins.
    NEEDS_BACKEND=1
    for arg in "$@"; do
        case "$arg" in
            --vhost-user-device|--vhost-user-device=*)
                NEEDS_BACKEND=0
                ;;
        esac
    done
fi

if [ "$NEEDS_BACKEND" = "0" ]; then
    exec "$SMOLVM_BIN" "$@"
fi

SOCK="${CONDUIT_SOCK:-/tmp/conduit-$$.sock}"
LOG="${CONDUIT_LOG:-/tmp/conduit-backend.log}"
WAIT_MS="${CONDUIT_WAIT_MS:-5000}"
DATA_SHM_NAME="${CONDUIT_DATA_SHM_NAME:-/conduit-data-$$}"

# In `-d` mode we hand the backend off to a detached watcher and
# clear BACKEND_PID before exiting, so the EXIT trap leaves the
# backend alive for the VM's lifetime.
cleanup() {
    if [ -n "${BACKEND_PID:-}" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
        wait "$BACKEND_PID" 2>/dev/null || true
    fi
    [ -n "${BACKEND_PID:-}" ] && rm -f "$SOCK"
}
trap cleanup EXIT INT TERM

# Start the backend in the background.
rm -f "$SOCK"
VIRTIO_CONDUIT_DATA_SHM_NAME="$DATA_SHM_NAME" \
    "$CONDUIT_BACKEND_BIN" --socket "$SOCK" >"$LOG" 2>&1 &
BACKEND_PID=$!
# Publish the conduit-backend pid for callers that own the orchestration
# (e.g. `bifrost orchestrate` waits on this file before attempting to
# attach control SHM).  Matches the contract qemu-launch-freebsd.sh
# implements; without it the orchestrator's 5-minute deadline fires
# even though the backend is up and serving on $SOCK.
if [ -n "${CONDUIT_BACKEND_PID_FILE:-}" ]; then
    printf '%s\n' "$BACKEND_PID" >"$CONDUIT_BACKEND_PID_FILE"
fi

# Wait for the socket to appear. Bounded loop so a backend that
# fails to start does not hang the launcher.
WAITED=0
while [ ! -S "$SOCK" ]; do
    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo "[smolvm-launch] conduit-backend exited before binding $SOCK" >&2
        echo "[smolvm-launch] last log lines:" >&2
        tail -n 20 "$LOG" >&2 || true
        exit 1
    fi
    if [ "$WAITED" -ge "$WAIT_MS" ]; then
        echo "[smolvm-launch] timed out waiting for $SOCK after ${WAIT_MS}ms" >&2
        exit 1
    fi
    sleep 0.05
    WAITED=$((WAITED + 50))
done

echo "[smolvm-launch] conduit-backend ready on $SOCK (pid $BACKEND_PID)" >&2

# Hand off to smolvm. The `--vhost-user-device` flag is the
# generic entry point on the smolvm side; it forwards each socket
# to `krun_add_vhost_user_device` (an optional libkrun symbol).
# Keep the flag before `--` so `machine run -- <guest command>`
# does not pass it into the guest argv.
ARGS=()
INSERTED=0
DETACHED=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        -d|--detach)
            DETACHED=1
            ARGS+=("$1")
            shift
            ;;
        --)
            ARGS+=("--vhost-user-device=$SOCK" "--")
            INSERTED=1
            shift
            while [ "$#" -gt 0 ]; do
                ARGS+=("$1")
                shift
            done
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done
if [ "$INSERTED" -eq 0 ]; then
    ARGS+=("--vhost-user-device=$SOCK")
fi

VIRTIO_CONDUIT_DATA_SHM_NAME="$DATA_SHM_NAME" \
    VIRTIO_CONDUIT_DATA_SHM_OPEN_EXISTING=1 \
    "$SMOLVM_BIN" "${ARGS[@]}" &
SMOLVM_PID=$!
set +e
wait "$SMOLVM_PID"
STATUS=$?
set -e
if [ "$STATUS" -ne 0 ]; then
    exit "$STATUS"
fi

# `machine run -d` returns after spawning the `_boot-vm` worker.
# Demo setup.sh scripts use that pattern inline (no `&`), so this
# launcher MUST return so the calling shell can continue. Spawn a
# detached watcher that kills the backend when boot-vm exits, then
# return.
if [ "$DETACHED" -eq 1 ]; then
    BOOT_PID=""
    for _ in {1..100}; do
        BOOT_PID="$(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || true)"
        [ -n "$BOOT_PID" ] && break
        sleep 0.1
    done
    if [ -n "$BOOT_PID" ]; then
        WATCH_SOCK="$SOCK"
        WATCH_BACKEND="$BACKEND_PID"
        nohup bash -c "
            while kill -0 '$BOOT_PID' 2>/dev/null; do sleep 0.5; done
            kill '$WATCH_BACKEND' 2>/dev/null || true
            rm -f '$WATCH_SOCK'
        " </dev/null >/dev/null 2>&1 &
        disown
        # Disarm EXIT-trap cleanup so the launcher's exit doesn't
        # kill the backend the watcher is shepherding.
        BACKEND_PID=""
    else
        echo "[smolvm-launch] WARN: no _boot-vm pid found after -d; backend will be torn down" >&2
    fi
fi
