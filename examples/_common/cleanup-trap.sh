#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# cleanup-trap.sh — idempotent cleanup hook sourced by run-demo.sh.
#
# Provides a single `demo_cleanup` function that the harness's
# EXIT/INT/TERM trap calls.  Safe to invoke multiple times — every
# step tolerates "already gone" state.
#
# Steps, in order:
#   1. sudo -n host/runtime/cleanup.sh   (kills bifrost, dtrace, stale _boot-vm)
#   2. pkill -KILL -f "examples/.*setup.sh"   (reaps the demo's
#      setup.sh / pgbench / redis-cli loop)
#   3. pkill -P $$                       (reaps direct children
#      spawned by run-demo.sh itself, e.g. the trace process)
#
# `sudo -n` is required: the user's NOPASSWD profile covers
# host/*/* paths but not bare `sudo -n true`, so we must invoke
# the script directly.
#
# This file is sourced, never executed.  It expects the caller to
# have set BIFROST_PROJECT_ROOT.

# Guard against double-sourcing.
if [ -n "${_BIFROST_CLEANUP_TRAP_SOURCED:-}" ]; then
    return 0
fi
_BIFROST_CLEANUP_TRAP_SOURCED=1

demo_cleanup() {
    # `set +e` so cleanup never aborts midway through teardown
    # because one of the kill targets is already dead.
    set +e

    local cleanup_sh="${BIFROST_PROJECT_ROOT:-}/host/runtime/cleanup.sh"
    if [ -x "$cleanup_sh" ]; then
        sudo -n "$cleanup_sh" >/dev/null 2>&1 || true
    fi

    # Stop smolvm.  Each demo's setup.sh calls
    # `"$SMOLVM" machine stop` in its own trap; we mirror that
    # here for the harness path.  `machine stop` is user-mode
    # (no sudo needed) — it talks to the smolvm daemon over a
    # local socket.
    #
    # `machine delete -f default` follows to wipe persistent
    # overlay state.  Upstream smolvm reuses a "default" machine's
    # overlay across `machine run -d` invocations even when --name
    # is omitted; demos expect a fresh rootfs, so without this a
    # prior demo's layer composition collides with the next and
    # surfaces as EUCLEAN (errno 117) at mount time.
    local smolvm_bin="${BIFROST_PROJECT_ROOT:-}/third_party/smolvm/target/release/smolvm"
    if [ -x "$smolvm_bin" ]; then
        DYLD_LIBRARY_PATH="${BIFROST_PROJECT_ROOT:-}/third_party/smolvm/lib" \
            "$smolvm_bin" machine stop >/dev/null 2>&1 || true
        DYLD_LIBRARY_PATH="${BIFROST_PROJECT_ROOT:-}/third_party/smolvm/lib" \
            "$smolvm_bin" machine delete -f default >/dev/null 2>&1 || true
    fi

    # Reap any examples/<demo>/setup.sh still running (and the
    # workload loops it spawned — pgbench, redis-cli ping loops,
    # curl floods, etc.).  -KILL because they typically ignore TERM
    # in their tight retry loops.
    pkill -KILL -f "examples/.*setup\.sh" 2>/dev/null || true

    # Belt and suspenders: kill any leftover smolvm runtime
    # process (the _boot-vm helper that hosts the libkrun VM).
    pkill -KILL -f "smolvm.*_boot-vm" 2>/dev/null || true

    # Direct children of the harness — the trace process,
    # background workload drivers — get a final reap pass.
    pkill -P $$ 2>/dev/null || true

    # Restore strict mode for the caller.
    set -e
}
