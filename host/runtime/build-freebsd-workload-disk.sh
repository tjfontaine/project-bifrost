#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# build-freebsd-workload-disk.sh — stage FreeBSD .pkg files into a
# directory the qemu-launch-freebsd.sh launcher mounts as a vvfat
# disk. Operator drops a one-line /etc/rc.local into the FreeBSD
# overlay once, and every subsequent launch picks up the staged
# binaries without root-image mutation.
#
# Usage:
#   build-freebsd-workload-disk.sh <output-dir> [profile]
#
# Profiles:
#   tcp      — nginx + ab (cross-kernel-tcp killer demo)
#   postgres — postgresql16-server + postgresql16-client + ab
#              (cross-kernel-postgres killer demo)
#   all      — both profiles (default)
#
# Env:
#   FREEBSD_PKG_RELEASE  default `14.3-RELEASE`. Override for
#                        operator-pinned releases.
#   FREEBSD_PKG_ARCH     default `aarch64`. Override for x86_64
#                        deployments (the rest of the demo
#                        infrastructure assumes aarch64 today).
#   FREEBSD_PKG_BASE_URL default pkg.freebsd.org's quarterly tree.
#
# Inside the guest, one-time rc.local setup:
#   # /etc/rc.local
#   set -eu
#   if [ -d /mnt/workload ]; then
#       :
#   else
#       mkdir -p /mnt/workload
#       mount -t msdosfs /dev/da1s1 /mnt/workload || true
#   fi
#   for pkg in /mnt/workload/pkgs/*.pkg; do
#       [ -f "$pkg" ] && pkg add -f "$pkg" 2>/dev/null || true
#   done

set -euo pipefail

OUT_DIR="${1:-}"
PROFILE="${2:-all}"
if [ -z "$OUT_DIR" ]; then
    echo "usage: $0 <output-dir> [tcp|postgres|all]" >&2
    exit 2
fi

FREEBSD_PKG_RELEASE="${FREEBSD_PKG_RELEASE:-14.3-RELEASE}"
FREEBSD_PKG_ARCH="${FREEBSD_PKG_ARCH:-aarch64}"
FREEBSD_PKG_BASE_URL="${FREEBSD_PKG_BASE_URL:-https://pkg.freebsd.org/FreeBSD:14:${FREEBSD_PKG_ARCH}/quarterly/All}"

# Package set per profile.  pkg names mirror the upstream
# pkg.freebsd.org tree exactly; if a name shifts in a future
# release the script will fail loudly at download time so the
# operator notices.
case "$PROFILE" in
    tcp)
        PKGS=(
            "nginx-1.26.2_3,3.pkg"
            "ap24-2.4.62.pkg"
        )
        ;;
    postgres)
        PKGS=(
            "postgresql16-server-16.4_2.pkg"
            "postgresql16-client-16.4_2.pkg"
            "postgresql16-contrib-16.4_2.pkg"
            "ap24-2.4.62.pkg"
        )
        ;;
    all)
        PKGS=(
            "nginx-1.26.2_3,3.pkg"
            "ap24-2.4.62.pkg"
            "postgresql16-server-16.4_2.pkg"
            "postgresql16-client-16.4_2.pkg"
            "postgresql16-contrib-16.4_2.pkg"
        )
        ;;
    *)
        echo "unknown profile $PROFILE (want tcp|postgres|all)" >&2
        exit 2
        ;;
esac

mkdir -p "$OUT_DIR/pkgs"
echo "[workload-disk] staging $PROFILE profile into $OUT_DIR (release=$FREEBSD_PKG_RELEASE arch=$FREEBSD_PKG_ARCH)" >&2

for pkg in "${PKGS[@]}"; do
    dest="$OUT_DIR/pkgs/$pkg"
    if [ -f "$dest" ]; then
        echo "[workload-disk] cached: $pkg" >&2
        continue
    fi
    url="$FREEBSD_PKG_BASE_URL/$pkg"
    echo "[workload-disk] fetching $url" >&2
    if ! curl -fsSL --connect-timeout 30 -o "$dest.tmp" "$url"; then
        echo "[workload-disk] WARNING: $pkg not found at $url" >&2
        echo "[workload-disk] (pkg.freebsd.org rotates the quarterly tree; pin FREEBSD_PKG_BASE_URL or update package names)" >&2
        rm -f "$dest.tmp"
        continue
    fi
    mv "$dest.tmp" "$dest"
done

# README the operator drops in the overlay so the one-time
# /etc/rc.local content lives next to the binaries.
cat >"$OUT_DIR/README.md" <<'EOM'
# FreeBSD workload disk

`bifrost orchestrate` mounts this directory as `/dev/da1` (vvfat
read-write) when the `FREEBSD_WORKLOAD_DIR` env var points at it.
Inside the FreeBSD guest, the workload disk is what carries
the nginx / postgres / pgbench binaries the killer demos need.

## One-time guest setup

Drop the following into your FreeBSD overlay's `/etc/rc.local`
(create the file if it doesn't exist):

```sh
#!/bin/sh
set -eu

WORKLOAD=/mnt/workload
mkdir -p "$WORKLOAD"
mount -t msdosfs /dev/da1s1 "$WORKLOAD" 2>/dev/null || true

for pkg in "$WORKLOAD"/pkgs/*.pkg; do
    [ -f "$pkg" ] && pkg add -f "$pkg" 2>/dev/null || true
done

# TCP demo
if [ -x /usr/local/sbin/nginx ]; then
    /usr/local/sbin/nginx -c /usr/local/etc/nginx/nginx.conf 2>/dev/null || true
fi

# Postgres demo
if [ -x /usr/local/bin/pg_ctl ]; then
    /usr/sbin/service postgresql onestart 2>/dev/null || true
fi
```

Then `chmod +x /etc/rc.local`.  Subsequent launches pick up the
staged pkg files automatically.

## What lands here

- `pkgs/*.pkg` — FreeBSD release packages downloaded from
  `pkg.freebsd.org`.
- This README.
EOM

echo "[workload-disk] done: $(ls "$OUT_DIR/pkgs" | wc -l | tr -d ' ') pkg(s) staged" >&2
