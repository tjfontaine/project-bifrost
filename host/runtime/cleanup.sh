#!/bin/sh
# bifrost cleanup: kill any leftover bifrost runner / dtrace processes
# from a hung or crashed run.
#
# Lives at host/runtime/cleanup.sh so the host/*/* NOPASSWD sudoers
# entry covers `sudo -n host/runtime/cleanup.sh`.

set -u

# Order matters: kill the runner first so it stops respawning anything,
# then the children. SIGTERM first, brief grace period, SIGKILL second.
# Match "bifrost" running as a CLI process, regardless of how it
# was invoked: from a build target, from host/runtime/, or via PATH
# (in which case ps just shows "bifrost"). The trailing space pins
# the match to bifrost-the-command (with args following), so it
# does NOT match `bifrost-uprobe`, `cargo build --bin bifrost`, or
# similar strings where bifrost is a substring or final token.
PATTERN_RUNNER='(^|/| )bifrost (-|attach |ls |--)'
PATTERN_DTRACE='dtrace -q -p [0-9]+ -s /tmp/bifrost-'
PATTERN_SMOLVM_BOOT='(^|/)smolvm _boot-vm .*/boot-config\.json'
# Orphan conduit-backends from smolvm-launch.sh detached-mode
# watchers that lost their VM (e.g. cleanup ran before the watcher
# noticed boot-vm exited).
PATTERN_CONDUIT_BACKEND='(^|/)conduit-backend (--socket|-s) /tmp/(conduit-|bifrost-orch-)'
# `bifrost orchestrate` spawns QEMU directly under the FreeBSD
# launcher; a hung orchestrate session leaks the qemu-system-aarch64
# child too.  Match by socket path so we never touch a hand-launched
# QEMU outside the orchestrator's namespace.
PATTERN_QEMU_ORCH='qemu-system-aarch64 .*-chardev socket,id=conduit,path=/tmp/(conduit-|bifrost-orch-)'

term_then_kill() {
    pat=$1
    pids=$(pgrep -f "$pat" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo "[cleanup] TERM: $pat -> $pids"
        kill -TERM $pids 2>/dev/null || true
    fi
}

kill_hard() {
    pat=$1
    pids=$(pgrep -f "$pat" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo "[cleanup] KILL: $pat -> $pids"
        kill -KILL $pids 2>/dev/null || true
    fi
}

term_then_kill "$PATTERN_RUNNER"
term_then_kill "$PATTERN_DTRACE"
term_then_kill "$PATTERN_SMOLVM_BOOT"
term_then_kill "$PATTERN_CONDUIT_BACKEND"
term_then_kill "$PATTERN_QEMU_ORCH"
# Bifrost needs a moment to flush libdtrace records, dump xagg
# totals, and release its OBSERVER_ATTACH slot. The xagg dump
# walks every (name,key) row to format a stderr table — fast for
# small tables but can take noticeably longer than 3s when
# aggregations have hundreds of distinct keys (every cc1 file
# open, etc.). Bumped to 10s; still well below any reasonable
# user-visible "is it stuck?" threshold.  Without this grace, a
# stuck observer slot blocks the next attach with "another
# bifrost observer is already attached" until smolvm restart.
sleep 10

kill_hard "$PATTERN_RUNNER"
kill_hard "$PATTERN_DTRACE"
kill_hard "$PATTERN_SMOLVM_BOOT"
kill_hard "$PATTERN_CONDUIT_BACKEND"
kill_hard "$PATTERN_QEMU_ORCH"
# Stale conduit-backend sockets (the watcher would have cleaned
# these up, but if it got killed too, sweep them now).
rm -f /tmp/conduit-*.sock /tmp/bifrost-orch-*-conduit.sock 2>/dev/null

# Stale wrapper files clutter /tmp.
rm -f /tmp/bifrost-*.ebpf /tmp/bifrost-*-host.d 2>/dev/null
# Stale orchestrator pidfiles + per-target launch logs.
rm -f /tmp/bifrost-orch-*-backend.pid /tmp/bifrost-orch-*-launch.log \
      /tmp/bifrost-orch-*-qemu.pid /tmp/bifrost-orch-*-qmp.sock \
      /tmp/bifrost-orch-*-conduit.log /tmp/bifrost-x2-orch.log 2>/dev/null

echo "[cleanup] done"
