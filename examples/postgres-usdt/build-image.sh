#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# build-image.sh — build the postgres-usdt-bench Docker image and
# push it to the local smolvm-reachable registry (default
# localhost:5005).  setup.sh then runs the image directly via
# `smolvm machine run --image localhost:5005/postgres-usdt-bench`.
#
# Why a registry rather than a smolvm pack: the Docker build
# pipeline is the predictable, reproducible thing developers know;
# smolvm pulls cleanly from any reachable registry via TSI.  The
# alternative (`smolvm pack create --from-vm` after a manual bake
# inside the VM) pays one-time cost in the same toolchain we already
# ship and trust.
#
# Knobs (env):
#   IMAGE_TAG    full image reference (default: localhost:5005/postgres-usdt-bench:latest)
#   PLATFORM     target arch (default: linux/arm64 — matches smolvm's aarch64 guest;
#                set to linux/amd64 on x86_64 macs)

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_TAG="${IMAGE_TAG:-localhost:5005/postgres-usdt-bench:latest}"

# Default to the host arch — smolvm guests are the same arch as the host.
case "$(uname -m)" in
    arm64|aarch64) DEFAULT_PLATFORM=linux/arm64 ;;
    x86_64)        DEFAULT_PLATFORM=linux/amd64 ;;
    *)             DEFAULT_PLATFORM=linux/$(uname -m) ;;
esac
PLATFORM="${PLATFORM:-$DEFAULT_PLATFORM}"

if ! command -v docker >/dev/null 2>&1; then
    echo "[build] docker not on PATH — install Docker Desktop or colima" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "[build] docker daemon not reachable — start it (Docker Desktop / colima)" >&2
    exit 1
fi

# Verify the registry is reachable.  Default vt-ferry-registry on
# port 5005; users with their own registry can override IMAGE_TAG.
REGISTRY_HOST=$(echo "$IMAGE_TAG" | cut -d/ -f1)
if ! curl -sf "http://${REGISTRY_HOST}/v2/_catalog" >/dev/null 2>&1; then
    echo "[build] registry $REGISTRY_HOST not reachable" >&2
    echo "[build]   start one with:" >&2
    echo "[build]     docker run -d --name vt-ferry-registry -p 5005:5000 registry:2" >&2
    exit 1
fi

echo "[build] docker build $IMAGE_TAG (platform=$PLATFORM)"
docker build --platform "$PLATFORM" -t "$IMAGE_TAG" "$SCRIPT_DIR"

echo "[build] docker push $IMAGE_TAG"
docker push "$IMAGE_TAG"

echo "[build] done — $IMAGE_TAG ready for smolvm to pull"
