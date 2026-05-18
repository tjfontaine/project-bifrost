#!/bin/sh
# kill-bifrost.sh — SIGTERM every bifrost runner WITHOUT touching
# smolvm.  Used by primer-sweep style harnesses that want to
# terminate a single primer's bifrost CLI between runs while
# keeping the shared smolvm VM alive across the whole sweep.
#
# Lives at host/runtime/kill-bifrost.sh so the host/*/* NOPASSWD
# sudoers entry covers `sudo -n host/runtime/kill-bifrost.sh`.

set -u

PATTERN_RUNNER='(^|/| )bifrost (-|attach |ls |--)'
PATTERN_DTRACE='dtrace -q -p [0-9]+ -s /tmp/bifrost-'

term_then_kill() {
    pat=$1
    pids=$(pgrep -f "$pat" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo "[kill-bifrost] TERM: $pat -> $pids"
        kill -TERM $pids 2>/dev/null || true
    fi
}

kill_hard() {
    pat=$1
    pids=$(pgrep -f "$pat" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo "[kill-bifrost] KILL: $pat -> $pids"
        kill -KILL $pids 2>/dev/null || true
    fi
}

term_then_kill "$PATTERN_RUNNER"
term_then_kill "$PATTERN_DTRACE"
sleep 1
kill_hard "$PATTERN_RUNNER"
kill_hard "$PATTERN_DTRACE"

echo "[kill-bifrost] done"
