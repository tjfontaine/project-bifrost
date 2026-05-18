# SPDX-License-Identifier: Apache-2.0
#
# postgres-usdt-bench — postgres pre-baked for the bifrost USDT demo.
#
# Predictable startup (the apt-install + initdb + pgbench-init steps
# that previously ran in the entrypoint at every smolvm boot are
# baked here once at image-build time).  The runtime entrypoint just
# copies the postgres binary to /workspace (ext4 — uprobes don't
# install on overlayfs), starts it, and drives a pgbench load loop.
#
# Build + push to the smolvm-reachable registry:
#   docker build -t localhost:5005/postgres-usdt-bench:latest examples/postgres-usdt/
#   docker push localhost:5005/postgres-usdt-bench:latest
# Or use the helper:
#   examples/postgres-usdt/build-image.sh

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install postgresql + pgbench (postgresql-contrib).  The apt
# postinst auto-runs initdb against /var/lib/postgresql/16/main with
# default config; we override pg_hba below to switch to trust auth.
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        postgresql postgresql-contrib sudo && \
    rm -rf /var/lib/apt/lists/*

# The entrypoint runs as the unprivileged `postgres` user (USER
# directive at end of file), but needs root for two surgical
# operations — copying the postgres binary from
# /usr/lib/postgresql/16/bin to /workspace (an ext4 mount provided
# by smolvm at runtime; the only path where uprobe install doesn't
# return -EIO on overlayfs) and chmodding it.  Grant exactly those
# two commands NOPASSWD; nothing else.
RUN echo 'postgres ALL=(root) NOPASSWD: /bin/cp /usr/lib/postgresql/16/bin/postgres /workspace/postgres, /bin/chmod 0755 /workspace/postgres' \
        > /etc/sudoers.d/postgres-usdt-bench-workspace && \
    chmod 0440 /etc/sudoers.d/postgres-usdt-bench-workspace

# Open up listen + auth so the TSI port-forward + pgbench can connect.
# Disable SSL: Ubuntu's postgres apt package enables SSL by default and
# expects the postgres user's supplementary `ssl-cert` group to grant
# read access to /etc/ssl/private/ssl-cert-snakeoil.key.  smolvm's
# crun runtime drops supplementary groups, so postgres can only see
# its primary group (`postgres`) — SSL startup fails with "Permission
# denied" on the snakeoil key, and postgres never binds.  We don't
# need SSL between pgbench and postgres on a localhost loopback in
# a sealed demo VM; switch ssl=off.
RUN sed -i "s|^#listen_addresses.*|listen_addresses = '0.0.0.0'|" \
        /etc/postgresql/16/main/postgresql.conf && \
    sed -i "s|^ssl = on|ssl = off|" \
        /etc/postgresql/16/main/postgresql.conf && \
    sed -i \
        -e 's|^local *all *all *peer$|local all all trust|' \
        -e 's|^local *all *postgres *peer$|local all postgres trust|' \
        -e 's|^host *all *all *127\.0\.0\.1/32 *scram-sha-256$|host all all 127.0.0.1/32 trust|' \
        -e 's|^host *all *all *::1/128 *scram-sha-256$|host all all ::1/128 trust|' \
        /etc/postgresql/16/main/pg_hba.conf && \
    sed -i "1i host all all 0.0.0.0/0 trust" \
        /etc/postgresql/16/main/pg_hba.conf

# Bake the bench dataset so cold-boot in smolvm skips the pgbench-init
# step entirely (pgbench-init requires postgres running, so all of
# this happens in a single RUN: start, populate, stop).
RUN pg_ctlcluster 16 main start && \
    su postgres -c "psql -c 'CREATE DATABASE bench'" && \
    su postgres -c "pgbench -i -s 5 -q bench" && \
    pg_ctlcluster 16 main stop --mode=fast

# Entrypoint: copy postgres → /workspace/postgres at boot (the
# /workspace mount is provided by smolvm at runtime, so this can't
# happen at image-build time), start postgres, drive pgbench load.
COPY entrypoint.sh /usr/local/bin/postgres-usdt-bench-entrypoint
RUN chmod 0755 /usr/local/bin/postgres-usdt-bench-entrypoint

EXPOSE 5432

# Drop to the `postgres` system user as the default container user.
# The entrypoint uses sudo for the two surgical root operations it
# needs (`cp` postgres binary into /workspace and `chmod`); sudoers
# above grants exactly those two commands and nothing else.  Postgres
# itself runs as the postgres user — the standard production posture.
USER postgres
ENTRYPOINT ["/usr/local/bin/postgres-usdt-bench-entrypoint"]
