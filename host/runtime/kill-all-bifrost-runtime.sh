#!/bin/sh
# kill-all-bifrost-runtime.sh — SIGTERM/SIGKILL every conduit-backend
# and smolvm _boot-vm process for the project-bifrost tree.  Used to
# wipe state between iterations of `bifrost orchestrate` debugging
# without having to track per-run PIDs by hand.
#
# Scope: matches by full command pattern containing
# `project-bifrost/host/runtime/conduit-backend` or
# `project-bifrost/third_party/smolvm/target/release/smolvm _boot-vm`.
# Outside processes (unrelated conduit-backends or smolvm VMs) are
# not touched.
#
# Lives at host/runtime/ so the project NOPASSWD sudoers entry
# (host/*/*) covers `sudo -n host/runtime/kill-all-bifrost-runtime.sh`.

set -u

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

term_then_kill() {
    pat=$1
    pids=$(pgrep -f "$pat" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo "[kill-all] TERM: $pat -> $pids"
        kill -TERM $pids 2>/dev/null || true
    fi
}

kill_hard() {
    pat=$1
    pids=$(pgrep -f "$pat" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo "[kill-all] KILL: $pat -> $pids"
        kill -KILL $pids 2>/dev/null || true
    fi
}

term_then_kill "${PROJECT_ROOT}/host/runtime/conduit-backend"
term_then_kill "${PROJECT_ROOT}/third_party/smolvm/target/release/smolvm _boot-vm"
# FreeBSD QEMU instances spawned by qemu-launch-freebsd.sh.  Match
# on the conduit socket path so we only catch bifrost-owned qemu
# processes, not unrelated qemu VMs the operator might have
# running.
term_then_kill "qemu-system-aarch64.*bifrost-orch-.*-conduit.sock"
sleep 1
kill_hard "${PROJECT_ROOT}/host/runtime/conduit-backend"
kill_hard "${PROJECT_ROOT}/third_party/smolvm/target/release/smolvm _boot-vm"
kill_hard "qemu-system-aarch64.*bifrost-orch-.*-conduit.sock"

echo "[kill-all] done"
