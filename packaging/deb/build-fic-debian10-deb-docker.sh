#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-fic-deb-builder:debian10}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-$ROOT_DIR/packaging/deb/Dockerfile.debian10}"
PACKAGE_VERSION="${1:-0.1.0}"

source "$ROOT_DIR/packaging/lib/build-resources.sh"
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

if [ "$CONTAINER_CMD" = "podman" ]; then
    CONTAINER_RUN_ARGS+=(--userns=keep-id)
fi

"$CONTAINER_CMD" build \
    "${FIC_CONTAINER_BUILD_ARGS[@]}" \
    -t "$IMAGE_NAME" \
    -f "$DOCKERFILE_PATH" \
    "$ROOT_DIR"

"$CONTAINER_CMD" run --rm \
    "${CONTAINER_RUN_ARGS[@]}" \
    --user "$(id -u):$(id -g)" \
    -e BUILD_JOBS="$BUILD_JOBS" \
    -e DEB_COMPRESSOR="${DEB_COMPRESSOR:-gzip}" \
    -e PACKAGE_DISTRO_TAG="${PACKAGE_DISTRO_TAG:-debian10}" \
    -e BUILD_ROOT="${BUILD_ROOT:-/tmp/fic-build-debian10}" \
    -e DIST_DIR="${DIST_DIR:-/workspace/dist}" \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace/packaging/deb \
    "$IMAGE_NAME" \
    ./build-fic-debian10-deb.sh "$PACKAGE_VERSION"
