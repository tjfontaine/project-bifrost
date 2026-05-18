#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — boot the shared bifrost-bench image in smolvm, then
# start a long-running in-guest exec that copies redis-server to
# /workspace and drives continuous redis-cli PING bursts. The
# uprobe attaches to
# processCommand inside the guest redis-server (resolved via the
# host CLI's ELF parse + BFR7 LOAD_PROG trailer).
#
# Symlink workaround: ubuntu's apt-installed `/usr/bin/redis-server`
# is a symlink to `redis-check-rdb` (multicall binary).  The kernel's
# `task->comm` may pick up the resolved binary's basename rather than
# the symlink's name, which the bifrost driver's container-aware
# uprobe path resolution then can't match.  Resolve the symlink to a
# real copy named `redis-server` so comm is unambiguous.
#
# By-symbol uprobes use a kernel task walk over the VM's root task
# namespace. Container entrypoint processes are not visible to that
# path today, so redis runs from `smolvm machine exec` instead.
#
# After this script reports "ready", open another shell and run
# bifrost yourself, dtrace-style:
#
#     sudo bifrost \
#         -p $(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || pgrep -f '_boot-vm.*boot-config' | tail -1) \
#         -s examples/redis-uprobe/probe.d
#
# When you are done tracing (^C the bifrost CLI), come back here
# and ^C this script too — it tears down the smolvm + ping loop.
#
# Knobs (env):
#   IMAGE          base image (default: localhost:5005/bifrost-bench:latest)
#   PING_BURST     PINGs per exec burst (default: 100)
#   BURSTS         number of bursts before the exec exits (default: 1200)

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
SMOLVM_BIN="$SMOLVM_DIR/target/release/smolvm"
SMOLVM="$PROJECT_ROOT/host/runtime/smolvm-launch.sh"
CLEANUP="$PROJECT_ROOT/host/runtime/cleanup.sh"
IMAGE="${IMAGE:-localhost:5005/bifrost-bench:latest}"
PING_BURST="${PING_BURST:-100}"
FIRE_GAP="${FIRE_GAP:-0.05}"
BURSTS="${BURSTS:-1200}"
BIFROST_ROOTFS="${BIFROST_ROOTFS:-/tmp/bifrost-redis-rootfs}"

export DYLD_LIBRARY_PATH="$SMOLVM_DIR/lib"
export SMOLVM_AGENT_ROOTFS="$SMOLVM_DIR/target/agent-rootfs"

cleanup() {
    echo
    echo "[setup] tearing down"
    sudo -n "$CLEANUP" 2>&1 | tail -2 || true
    "$SMOLVM" machine stop 2>&1 | tail -2 || true
    pkill -P $$ 2>/dev/null || true
    exit 0
}
trap cleanup INT TERM

echo "[setup] cleanup leftover bifrost / smolvm processes"
sudo -n "$CLEANUP" 2>&1 | tail -2 || true
"$SMOLVM" machine stop 2>&1 | tail -2 || true
sleep 1

echo "[setup] launching $IMAGE on smolvm — temporary idle boot for rootfs mirror"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image "$IMAGE" \
    2>&1 | tail -3

PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
echo "[setup] smolvm pid=$PID — preparing host uprobe rootfs mirror"
mkdir -p "$BIFROST_ROOTFS/workspace"
"$SMOLVM" machine exec -- sh -c '
    set -e
    command -v redis-server >/dev/null
    src=$(readlink -f "$(command -v redis-server)")
    cp "$src" /workspace/redis-server
    chmod 0755 /workspace/redis-server
'
"$SMOLVM" machine cp default:/workspace/redis-server "$BIFROST_ROOTFS/workspace/redis-server"
chmod 0755 "$BIFROST_ROOTFS/workspace/redis-server"

echo "[setup] starting redis workload in guest exec"
(
    "$SMOLVM" machine exec -- sh -c "
            set -e
            command -v redis-server >/dev/null
            command -v redis-cli >/dev/null
            rm -f /tmp/bifrost-redis.sock
            rm -f /tmp/bifrost-redis.rdb
            /workspace/redis-server \
                --port 0 \
                --unixsocket /tmp/bifrost-redis.sock \
                --unixsocketperm 777 \
                --save '' \
                --appendonly no \
                --dir /tmp \
                --dbfilename bifrost-redis.rdb &
            REDIS_PID=\$!
            for i in \$(seq 1 30); do
                if redis-cli -s /tmp/bifrost-redis.sock ping >/dev/null 2>&1; then
                    break
                fi
                sleep 0.5
            done
            burst=0
            while kill -0 \$REDIS_PID 2>/dev/null && [ \$burst -lt $BURSTS ]; do
                for i in \$(seq 1 $PING_BURST); do
                    redis-cli -s /tmp/bifrost-redis.sock ping >/dev/null 2>&1 || true
                done
                burst=\$((burst + 1))
                sleep $FIRE_GAP
            done
            kill \$REDIS_PID 2>/dev/null || true
            wait \$REDIS_PID
        "
) >/tmp/bifrost-redis-workload.log 2>&1 &
WORKLOAD_PID=$!

echo "[setup] redis workload pid=$WORKLOAD_PID — letting redis + PING loop settle"
sleep 5

cat <<MSG

[setup] ════════════════════════════════════════════════════════════
[setup] ready. redis on guest /tmp/bifrost-redis.sock, smolvm pid=$PID
[setup]
[setup] in another shell, run bifrost (dtrace-style):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -s examples/redis-uprobe/probe.d
[setup]
[setup] this shell idles while the guest exec drives redis-cli PINGs.
[setup] ════════════════════════════════════════════════════════════

MSG

echo "[setup] workload running in guest exec. ^C to tear down."
while :; do sleep 60; done
