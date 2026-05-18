#!/bin/bash
# Mirror everything to /workspace/entrypoint.log so smolvm `-d` mode
# (which discards container stdout/stderr) doesn't hide failures.
exec > >(tee -a /workspace/entrypoint.log) 2>&1
echo "[entrypoint] $(date '+%T') started uid=$(id -u) gid=$(id -g) groups=$(id -G)"
# SPDX-License-Identifier: Apache-2.0
#
# postgres-usdt-bench entrypoint — runs as the `postgres` user (per
# Dockerfile USER directive).  Two surgical sudo escalations cover
# the workspace setup; everything else stays unprivileged.
#
# What we do at boot:
#   1. Copy /usr/lib/postgresql/16/bin/postgres → /workspace/postgres
#      (the /workspace mount is provided by smolvm at runtime; we
#      need an ext4 inode because uprobe_register returns -EIO on
#      overlayfs).
#   2. Start postgres (the cluster, pg_hba, and the `bench` database
#      with pgbench-init data are all baked into the image).
#   3. Drive a continuous pgbench -c 4 load loop in the background
#      so bifrost has steady traffic to trace.
#   4. Wait on postgres (PID 1 of the container) — when the bifrost
#      driver attaches a uprobe to /workspace/postgres, the kernel's
#      `find_task_by_comm("postgres")` lookup will match this
#      process and resolve `.note.stapsdt` from its exe_file.

set -e

PG_VER=16
PG_BIN=/usr/lib/postgresql/$PG_VER/bin/postgres

# 0. Ensure the `postgres` user exists.  smolvm's persistent overlay
# is shared by default across image runs (persistent_overlay_id is
# always "default" unless --name is set), so a prior run with a
# bench image that lacks /etc/passwd: postgres can shadow our
# image's lower-layer /etc/passwd via the upper layer.  When that
# happens the `su postgres -c ...` below silently no-ops, postgres
# never starts, and the USDT probes never fire.  Idempotent useradd
# restores the user with the canonical IDs (uid 999, gid 999 — the
# defaults from postgresql-common's adduser invocation).
if ! id -u postgres >/dev/null 2>&1; then
    echo "[entrypoint] postgres user missing — recreating (overlay drift)" >&2
    if ! getent group postgres >/dev/null 2>&1; then
        groupadd -r -g 999 postgres
    fi
    useradd -r -u 999 -g postgres -d /var/lib/postgresql -s /bin/bash postgres
    # The data directory must be owned by the postgres uid for
    # postgres to start.  Restore ownership in case the upper
    # layer has stale uid mappings.
    chown -R postgres:postgres /var/lib/postgresql /etc/postgresql 2>/dev/null || true
fi

# 1. Copy postgres binary to /workspace (ext4) — only on first boot;
# the persistent overlay preserves /workspace across runs.  We need
# root for the cp (the directory is owned by root mode 0755); call
# `sudo` from the postgres user OR run the cp directly when we're
# already root.  smolvm's `machine run -d` ignores the Dockerfile
# USER directive and starts the container as uid=0 — handle both.
if [ ! -x /workspace/postgres ]; then
    echo '[entrypoint] copying postgres -> /workspace/postgres' >&2
    if [ "$(id -u)" = "0" ]; then
        cp /usr/lib/postgresql/16/bin/postgres /workspace/postgres
        chmod 0755 /workspace/postgres
    else
        sudo /bin/cp /usr/lib/postgresql/16/bin/postgres /workspace/postgres
        sudo /bin/chmod 0755 /workspace/postgres
    fi
fi

# 2. Start postgres from the /workspace copy so its inode is the
# ext4 one — uprobe install succeeds against ext4, fails against
# overlayfs.  task->comm becomes "postgres" from argv[0]'s basename.
# Postgres refuses to run as root; drop privileges via su if needed.
if [ "$(id -u)" = "0" ]; then
    su postgres -c "/workspace/postgres -D /var/lib/postgresql/$PG_VER/main \
        -c config_file=/etc/postgresql/$PG_VER/main/postgresql.conf" &
else
    /workspace/postgres -D /var/lib/postgresql/$PG_VER/main \
        -c config_file=/etc/postgresql/$PG_VER/main/postgresql.conf &
fi
PGPID=$!

# Wait for postgres to accept connections, then drive load.
for _ in $(seq 1 60); do
    psql -h 127.0.0.1 -U postgres -p 5432 -d postgres \
        -c 'SELECT 1' >/dev/null 2>&1 && break
    sleep 1
done

# 3. Continuous pgbench load loop in the background.  Filter to just
# the summary lines so the container log stays terse.
(
    while :; do
        pgbench -h 127.0.0.1 -U postgres -p 5432 \
            -c 4 -t 200 bench 2>&1 \
            | grep -E 'tps|latency average' \
            | sed 's/^/[pgbench-load] /'
    done
) &

# 4. Block on postgres so the container stays alive until SIGTERM.
wait $PGPID
