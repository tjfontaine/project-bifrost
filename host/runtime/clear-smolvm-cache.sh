#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# clear-smolvm-cache.sh — drop root-owned smolvm VM cache dirs left
# behind by a prior `sudo`-invoked run, so subsequent unprivileged
# `smolvm machine run` invocations can write their config/PID files.
#
# A previous run inside this project landed several files under
# `~/Library/Caches/smolvm/vms/<id>/` owned by root rather than the
# invoking user. smolvm's CLI then fails with `Permission denied
# (os error 13)` when it tries to overwrite the per-VM config or
# PID file. This script removes those root-owned per-VM dirs.
#
# Scope: ONLY operates inside `${HOME}/Library/Caches/smolvm/vms/`.
# Refuses to delete anything outside that prefix. The parent
# directory itself is preserved (it's user-owned).
#
# Usage:
#   sudo -n host/runtime/clear-smolvm-cache.sh        # all root-owned dirs
#   sudo -n host/runtime/clear-smolvm-cache.sh <id>   # one specific VM id
#
# Lives at host/runtime/ so the project NOPASSWD sudoers entry
# (host/*/*) covers `sudo -n host/runtime/clear-smolvm-cache.sh`.

set -eu

# Prefer SUDO_USER's home when invoked under sudo so we touch the
# actual user's cache, not root's.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    USER_HOME=$(eval echo "~${SUDO_USER}")
else
    USER_HOME="${HOME:-}"
fi

if [ -z "$USER_HOME" ] || [ ! -d "$USER_HOME" ]; then
    echo "[clear-smolvm-cache] could not resolve user home" >&2
    exit 1
fi

CACHE_DIR="$USER_HOME/Library/Caches/smolvm/vms"
if [ ! -d "$CACHE_DIR" ]; then
    echo "[clear-smolvm-cache] no cache dir at $CACHE_DIR (nothing to do)"
    exit 0
fi

# Hard safety net: refuse if the resolved path is not under the
# Library/Caches/smolvm/vms prefix.
case "$CACHE_DIR" in
    */Library/Caches/smolvm/vms) : ;;
    *) echo "[clear-smolvm-cache] refusing to operate on $CACHE_DIR" >&2; exit 1 ;;
esac

if [ "$#" -gt 0 ]; then
    # Specific id mode. Validate the id is a 16-hex-char dir name.
    case "$1" in
        [0-9a-f]*) : ;;
        *) echo "[clear-smolvm-cache] bad id: $1" >&2; exit 1 ;;
    esac
    TARGET="$CACHE_DIR/$1"
    if [ ! -e "$TARGET" ]; then
        echo "[clear-smolvm-cache] $TARGET not present"
        exit 0
    fi
    echo "[clear-smolvm-cache] removing $TARGET"
    rm -rf -- "$TARGET"
    echo "[clear-smolvm-cache] done"
    exit 0
fi

# Bulk mode: walk every per-VM dir, remove any whose top-level
# entries include a root-owned file/dir.
removed=0
kept=0
for d in "$CACHE_DIR"/*; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    # Only touch 16-hex-char vm-id dirs (skip anything else).
    case "$name" in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) : ;;
        *) continue ;;
    esac
    # If any top-level entry is root-owned, drop the whole dir.
    has_root=0
    for f in "$d"/* "$d"/.[!.]* "$d"; do
        [ -e "$f" ] || continue
        owner=$(stat -f %u "$f" 2>/dev/null || echo "")
        if [ "$owner" = "0" ]; then
            has_root=1
            break
        fi
    done
    if [ "$has_root" = "1" ]; then
        echo "[clear-smolvm-cache] removing root-owned $d"
        rm -rf -- "$d"
        removed=$((removed + 1))
    else
        kept=$((kept + 1))
    fi
done

echo "[clear-smolvm-cache] removed=$removed kept=$kept"
