#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-fic-deb-builder:ubuntu2604}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-$ROOT_DIR/packaging/deb/Dockerfile.ubuntu2604}"

source "$ROOT_DIR/packaging/lib/build-resources.sh"
source "$ROOT_DIR/packaging/lib/version-contract.sh"
fic_configure_product_version "$@"
fic_configure_build_resources
fic_configure_container_resources
fic_apply_build_priority

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
CONTAINER_RUN_ARGS=("${FIC_CONTAINER_RUN_ARGS[@]}")

"$CONTAINER_CMD" build \
    "${FIC_CONTAINER_BUILD_ARGS[@]}" \
    -t "$IMAGE_NAME" \
    -f "$DOCKERFILE_PATH" \
    "$ROOT_DIR"

"$CONTAINER_CMD" run --rm \
    "${CONTAINER_RUN_ARGS[@]}" \
    -e BUILD_JOBS="$BUILD_JOBS" \
    -e DEB_COMPRESSOR="${DEB_COMPRESSOR:-gzip}" \
    -e FIC_BUILD_COMMIT="${FIC_BUILD_COMMIT:-unknown}" \
    -e FIC_RELEASE_TAG="${FIC_RELEASE_TAG:-none}" \
    -e FIC_RELEASE_BUILD="${FIC_RELEASE_BUILD:-OFF}" \
    -e BUILD_ROOT="${BUILD_ROOT:-/tmp/fic-build-ubuntu2604}" \
    -e DIST_DIR="${DIST_DIR:-/workspace/dist}" \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace/packaging/deb \
    "$IMAGE_NAME" \
    ./build-fic-ubuntu2604-deb.sh "$FIC_PRODUCT_VERSION"
