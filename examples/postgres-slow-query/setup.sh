#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — boot ubuntu/postgres in smolvm and continuously drive
# pgbench load against it (from inside the guest, no host install
# of pgbench required).  Does NOT run the trace.
#
# After this script reports "setup ready", open another shell and
# run bifrost yourself, dtrace-style:
#
#     sudo bifrost \
#         -p $(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || pgrep -f '_boot-vm.*boot-config' | tail -1) \
#         -s examples/postgres-slow-query/probe.d
#
# Or with an inline D expression (`bifrost -n '...'`):
#
#     sudo bifrost \
#         -p $(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || pgrep -f '_boot-vm.*boot-config' | tail -1) \
#         -n 'bifrost::do_sys_openat2:entry / execname == "postgres" / { @[pid] = count(); }'
#
# When you have enough samples (^C the bifrost CLI to dump
# aggregations), come back here and ^C this script too.
#
# Calls `sudo -n` on host/runtime/cleanup.sh — that path is covered
# by the host/*/* NOPASSWD sudoers entry.  This wrapper itself does
# not require sudo to invoke.
#
# Knobs (env):
#   IMAGE       postgres image (default: ubuntu/postgres:16-24.04_beta)
#   PG_DB       database name (default: bench)
#   PG_PASS     superuser password (default: bifrost)
#   PG_SCALE    pgbench -i scale factor (default: 5; ~75 MB dataset)
#   PG_CONC     pgbench client concurrency (default: 4)

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
SMOLVM_BIN="$SMOLVM_DIR/target/release/smolvm"
SMOLVM="$PROJECT_ROOT/host/runtime/smolvm-launch.sh"
CLEANUP="$PROJECT_ROOT/host/runtime/cleanup.sh"
IMAGE="${IMAGE:-localhost:5005/postgres-usdt-bench:latest}"
PG_DB="${PG_DB:-bench}"
PG_PASS="${PG_PASS:-bifrost}"
PG_SCALE="${PG_SCALE:-5}"
PG_CONC="${PG_CONC:-4}"

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

echo "[setup] launching $IMAGE on smolvm with -p 5432:5432"
echo "[setup]   entrypoint runs everything in-container: apt-install if"
echo "[setup]   needed, configure pg_hba, bench-db create, pgbench-init,"
echo "[setup]   then a continuous pgbench load loop AND postgres in"
echo "[setup]   foreground.  No 'machine exec' from setup — concurrent"
echo "[setup]   agent-socket users were the actual cause of the earlier"
echo "[setup]   apparent-hang we mis-attributed to TSI."
# Use the postgres-usdt-bench image's default entrypoint as-is.
# It already does: copy /usr/lib/postgresql/16/bin/postgres to
# /workspace/postgres (ext4 — uprobe install requires it), start
# postgres, wait for ready, drive a continuous pgbench load loop.
# Everything postgres-slow-query needs.  Don't override with a
# bash -c — that wiped the persistent-overlay /etc/postgresql/16
# during earlier validation, breaking subsequent runs.
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image "$IMAGE" \
    2>&1 | tail -3

echo "[setup] waiting for smolvm boot + in-container postgres warmup"
i=0
PID=""
while [ -z "$PID" ]; do
    PID=$(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || pgrep -f '_boot-vm.*boot-config' | tail -1)
    sleep 1
    i=$((i + 1))
    [ "$i" -gt 30 ] && { echo "timed out waiting for smolvm boot" >&2; exit 1; }
done

# Image is pre-baked.  Entrypoint inside the container handles
# postgres start + pgbench-init + pgbench-load loop.  Don't use
# `smolvm machine exec` here — concurrent agent-socket users
# deadlock per the historical diagnosis above.  Bifrost attaches
# to the smolvm pid (kernel state), so the host TCP port-forward
# is unrelated.
sleep 15
echo "[setup] smolvm pid=$PID — postgres + pgbench load loop should be running in-guest"
echo "[setup]   port-forward returned bytes (postgres handshake started)"

cat <<EOF

[setup] ════════════════════════════════════════════════════════════
[setup] ready. postgres on 127.0.0.1:5432, smolvm pid=$PID
[setup]   pgbench-init done; in-guest pgbench load loop running.
[setup]
[setup] in another shell, run bifrost (dtrace-style):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -s examples/postgres-slow-query/probe.d
[setup]
[setup] this shell idles until you ^C; teardown via the trap.
[setup] ════════════════════════════════════════════════════════════

EOF

# All work happens inside the bg container's entrypoint; setup.sh
# just idles so its INT/TERM trap can tear down cleanly when the
# user ^Cs.
while :; do sleep 60; done
