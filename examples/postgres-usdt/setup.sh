#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — boot the pre-baked postgres-usdt-bench image in smolvm
# and idle until you ^C.  The image (built via
# `examples/postgres-usdt/build-image.sh`) carries postgresql,
# postgresql-contrib, the bench DB, and a narrow sudoers rule that
# lets the setup workload copy postgres onto the smolvm /workspace
# disk before starting it there.
#
# After this script reports "ready", open another shell and run
# bifrost:
#
#     sudo bifrost \
#         -p $(pgrep -n -f '_boot-vm.*boot-config' 2>/dev/null || pgrep -f '_boot-vm.*boot-config' | tail -1) \
#         -s examples/postgres-usdt/probe.d
#
# When you ^C the bifrost CLI it dumps aggregations.  Then ^C this
# script too — it tears down the smolvm VM.
#
# Calls `sudo -n` on host/runtime/cleanup.sh — that path is covered
# by the host/*/* NOPASSWD sudoers entry.  This wrapper itself does
# not require sudo to invoke.
#
# Knobs (env):
#   IMAGE_TAG   full image reference (default: localhost:5005/postgres-usdt-bench:latest)

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SMOLVM_DIR="$PROJECT_ROOT/third_party/smolvm"
SMOLVM_BIN="$SMOLVM_DIR/target/release/smolvm"
SMOLVM="$PROJECT_ROOT/host/runtime/smolvm-launch.sh"
CLEANUP="$PROJECT_ROOT/host/runtime/cleanup.sh"
IMAGE_TAG="${IMAGE_TAG:-localhost:5005/postgres-usdt-bench:latest}"

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

# Force a clean persistent overlay.  postgres-usdt depends on the
# image-baked /etc/passwd having the `postgres` user (the entrypoint
# runs `su postgres -c ...`).  smolvm's persistent overlay uses
# `persistent_overlay_id: "default"` unconditionally and accumulates
# upper-layer changes across image runs — `bifrost-bench` runs in
# the same overlay before this demo can shadow image-baked
# /etc/passwd entries, making `su postgres` no-op silently.  Even
# after we rebuild postgres-usdt-bench with an idempotent useradd
# in entrypoint.sh, smolvm's layer cache logic occasionally fails
# to merge the new image's layers cleanly (observed:
# "layer directory is empty" warnings in agent-console.log
# followed by a fallback "physically merging layers" path that
# can leave stale entrypoint binaries in place).
#
# `machine delete -f default` clears the overlay and storage
# disks for the default machine, forcing the next run to re-pull
# the image fresh and start from a clean upper layer.  Cost: one
# cold-pull per run (~5–15 s); benefit: deterministic state.
echo "[setup] resetting default machine to force fresh image pull"
"$SMOLVM" machine delete -f default 2>&1 | tail -2 || true
sleep 1

# Image-pull pre-flight — surface a useful diagnostic before the
# smolvm machine run if the image is missing from the local registry.
REGISTRY_HOST=$(echo "$IMAGE_TAG" | cut -d/ -f1)
IMAGE_NO_TAG=$(echo "$IMAGE_TAG" | sed 's|:[^/]*$||' | cut -d/ -f2-)
TAG=$(echo "$IMAGE_TAG" | grep -oE ':[^/]*$' | tr -d ':')
TAG=${TAG:-latest}
ACCEPT_HEADERS='-H Accept:application/vnd.oci.image.index.v1+json -H Accept:application/vnd.oci.image.manifest.v1+json -H Accept:application/vnd.docker.distribution.manifest.v2+json -H Accept:application/vnd.docker.distribution.manifest.list.v2+json'
if ! curl -sf $ACCEPT_HEADERS "http://${REGISTRY_HOST}/v2/${IMAGE_NO_TAG}/manifests/${TAG}" >/dev/null 2>&1; then
    cat <<EOF >&2
[setup] image not found in registry: $IMAGE_TAG
[setup]   build + push first:
[setup]     examples/postgres-usdt/build-image.sh
EOF
    exit 1
fi

echo "[setup] launching $IMAGE_TAG on smolvm — entrypoint idles"
RUST_LOG=info \
    "$SMOLVM" machine run -d --net \
        --image "$IMAGE_TAG" \
        -- bash -c 'sleep infinity' \
    2>&1 | tail -3

# Bifrost trace targets the smolvm pid (kernel state) — the host
# TCP port-forward to 5432 is unrelated to whether USDT probes fire.
# USDT resolution uses the VM-visible /workspace/postgres path, so run
# postgres from a VM-level exec after staging it onto the ext4 disk.
echo "[setup] waiting for smolvm boot"
i=0
PID=""
while [ -z "$PID" ]; do
    PID=$("$PROJECT_ROOT/examples/_common/smolvm-pid.sh" || true)
    sleep 1
    i=$((i + 1))
    [ "$i" -gt 30 ] && { echo "timed out waiting for smolvm boot" >&2; exit 1; }
done

echo "[setup] starting VM-visible postgres + SQL loop"
(
    "$SMOLVM" machine exec -- sh -c '
        set -e
        # Upstream `smolvm machine exec` lands in the container as
        # root; postgres refuses to run as root. Drop into the
        # postgres user for the workload. (Previously the script
        # ran as the container USER directly, so `sudo -n` was the
        # privilege-escalation path. Now it is the opposite.)
        cp /usr/lib/postgresql/16/bin/postgres /workspace/postgres
        chmod 0755 /workspace/postgres
        chown postgres:postgres /workspace/postgres
        su postgres -c "/workspace/postgres \
            -D /var/lib/postgresql/16/main \
            -c config_file=/etc/postgresql/16/main/postgresql.conf \
            -k /tmp \
            >/tmp/postgres-usdt.log 2>&1 &
        PG_PID=\$!
        for i in \$(seq 1 40); do
            if pg_isready -h /tmp >/dev/null 2>&1; then
                break
            fi
            sleep 0.25
        done
        while kill -0 \"\$PG_PID\" 2>/dev/null; do
            psql -h /tmp -U postgres -d postgres -qAt \
                -c \"begin; select 1; commit;\" >/dev/null 2>&1 || true
        done"
    '
) >/tmp/bifrost-postgres-usdt-workload.log 2>&1 &
WORKLOAD_PID=$!

sleep 5
echo "[setup] smolvm pid=$PID — postgres workload pid=$WORKLOAD_PID"

cat <<EOF

[setup] ════════════════════════════════════════════════════════════
[setup] ready. postgres workload running in VM exec, smolvm pid=$PID
[setup]
[setup] in another shell, run bifrost (dtrace-style):
[setup]
[setup]   sudo bifrost -p $PID \\
[setup]       -s examples/postgres-usdt/probe.d
[setup]
[setup] this shell idles until you ^C; teardown via the trap.
[setup] ════════════════════════════════════════════════════════════

EOF

while :; do sleep 60; done
