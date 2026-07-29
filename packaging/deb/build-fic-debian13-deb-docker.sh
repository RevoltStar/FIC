#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-fic-deb-builder:debian13}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-$ROOT_DIR/packaging/deb/Dockerfile.debian13}"
PACKAGE_VERSION="${1:-0.1.0}"

find_container_command() {
    if command -v podman >/dev/null 2>&1; then
        printf '%s\n' "podman"
        return 0
    fi

    if command -v docker >/dev/null 2>&1; then
        printf '%s\n' "docker"
        return 0
    fi

    echo "Missing required command: podman or docker" >&2
    exit 1
}

CONTAINER_CMD="$(find_container_command)"
CONTAINER_RUN_ARGS=()

"$CONTAINER_CMD" build -t "$IMAGE_NAME" -f "$DOCKERFILE_PATH" "$ROOT_DIR"

"$CONTAINER_CMD" run --rm \
    "${CONTAINER_RUN_ARGS[@]}" \
    -e DEB_COMPRESSOR="${DEB_COMPRESSOR:-gzip}" \
    -e BUILD_ROOT="${BUILD_ROOT:-/tmp/fic-build-debian13}" \
    -e DIST_DIR="${DIST_DIR:-/workspace/dist}" \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace/packaging/deb \
    "$IMAGE_NAME" \
    ./build-fic-debian13-deb.sh "$PACKAGE_VERSION"
