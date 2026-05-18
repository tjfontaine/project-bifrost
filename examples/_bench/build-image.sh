#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# build-image.sh — build the shared bifrost-bench image and push
# it to the smolvm-reachable local registry (default
# localhost:5005).  Each demo's setup.sh runs the image directly
# via `smolvm machine run --image localhost:5005/bifrost-bench`,
# replacing per-boot apt-install with a pre-baked artifact.
#
# Image carries every apt dep across the demos under examples/:
# postgres, nginx, redis, stress-ng, build-essential, etc.  See
# examples/_bench/Dockerfile for the full list.
#
# Knobs (env):
#   IMAGE_TAG    full image reference
#                (default: localhost:5005/bifrost-bench:latest)
#   PLATFORM     target arch (auto-detected from `uname -m`;
#                set to override on cross-arch builds)

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_TAG="${IMAGE_TAG:-localhost:5005/bifrost-bench:latest}"

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

echo "[build] building $IMAGE_TAG for $PLATFORM"
docker buildx build \
    --platform "$PLATFORM" \
    --tag "$IMAGE_TAG" \
    --push \
    "$SCRIPT_DIR"

echo "[build] done — image $IMAGE_TAG is in the local registry"
echo "[build] each demo's setup.sh now picks it up via --image $IMAGE_TAG"
