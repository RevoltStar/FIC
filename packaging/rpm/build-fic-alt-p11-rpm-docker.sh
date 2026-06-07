#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-fic-rpm-builder:alt-p11}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-$ROOT_DIR/packaging/rpm/Dockerfile}"
PACKAGE_VERSION="${1:-0.1.0}"

find_container_command() {
    if command -v podman >/dev/null              2>&1; then
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

if [ "$CONTAINER_CMD" = "podman" ]; then
    CONTAINER_RUN_ARGS+=(--userns=keep-id)
fi

"$CONTAINER_CMD" build -t "$IMAGE_NAME" -f "$DOCKERFILE_PATH" "$ROOT_DIR"

"$CONTAINER_CMD" run --rm \
    "${CONTAINER_RUN_ARGS[@]}" \
    --user "$(id -u):$(id -g)" \
    -e BUILD_ROOT="${BUILD_ROOT:-/tmp/fic-build-rpm}" \
    -e DIST_DIR="${DIST_DIR:-/workspace/dist}" \
    -e RPM_TOPDIR="${RPM_TOPDIR:-/tmp/fic-rpmbuild}" \
    -e RPM_RELEASE="${RPM_RELEASE:-1.altp11}" \
    -v "$ROOT_DIR:/workspace" \
    -w /workspace/packaging/rpm \
    "$IMAGE_NAME" \
    ./build-fic-alt-p11-rpm.sh "$PACKAGE_VERSION"
