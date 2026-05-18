# SPDX-License-Identifier: Apache-2.0
#
# bifrost-bench — single shared image with every apt-install
# dependency the bifrost demos need pre-baked.  Replaces the
# per-demo "apt-get install at first boot" pattern that made
# cold-starts unpredictable (postgres-slow-query took 2-3 min
# on first run, others 30-90 s).
#
# Each demo's entrypoint scripts inline the workload using these
# pre-installed binaries, so smolvm boot becomes "fork the
# entrypoint, run the workload" — no apt at runtime, no network
# dependency at boot.
#
# Build + push to the smolvm-reachable local registry:
#     examples/_bench/build-image.sh
#
# Demos that consume this image:
#   - intra-guest-http     (nginx + apache2-utils)
#   - cross-domain-http    (nginx + apache2-utils)
#   - redis-uprobe         (redis-server)
#   - compile-profile      (build-essential + curl + ncat)
#   - postgres-slow-query  (postgresql + postgresql-contrib)
#   - scheduler-offcpu     (stress-ng)
#   - sched-multi          (stress-ng)
#
# postgres-usdt has its own image (postgres-usdt-bench) because
# it bakes additional state (pgbench-init dataset, custom
# pg_hba.conf, ssl=off).  Its Dockerfile predates this shared
# image and stays as-is for the USDT demo's specific needs.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Single layer — every dep across the demos.  Ordering follows
# install size (largest first) to maximize layer cache hits when
# adding a new package later.
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        postgresql postgresql-contrib \
        nginx apache2-utils \
        redis-server \
        stress-ng \
        build-essential \
        curl ca-certificates unzip ncat \
        sudo procps && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Some demos rebind nginx / redis to 0.0.0.0 (rather than
# 127.0.0.1) so the TSI port-forward can reach them.  Apply the
# config tweak here so per-demo entrypoints don't have to.
RUN sed -i 's|listen 80 default_server;|listen 0.0.0.0:80 default_server;|' \
        /etc/nginx/sites-available/default && \
    sed -i 's|^bind .*|bind 0.0.0.0 -::*|' /etc/redis/redis.conf 2>/dev/null || true

# Default entrypoint is /bin/sh — each demo's setup.sh passes its
# own `-- <command>` to override.  No CMD specified.
