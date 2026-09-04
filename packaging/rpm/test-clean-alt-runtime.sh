#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RPM_DIR="${1:-$ROOT_DIR/dist}"
IMAGE_NAME="${IMAGE_NAME:-fic-rpm-runtime-test:alt-p11}"
CONTAINER_CMD="${CONTAINER_CMD:-podman}"

"$CONTAINER_CMD" build \
    -t "$IMAGE_NAME" \
    -f "$ROOT_DIR/packaging/rpm/Dockerfile.runtime-test" \
    "$ROOT_DIR"

"$CONTAINER_CMD" run --rm \
    -e FIC_DISPOSABLE_ALT_RUNTIME_TEST=1 \
    -e HTTP_PROXY= \
    -e HTTPS_PROXY= \
    -e ALL_PROXY= \
    -e http_proxy= \
    -e https_proxy= \
    -e all_proxy= \
    -e NO_PROXY='*' \
    -e no_proxy='*' \
    -v "$ROOT_DIR:/workspace:ro" \
    -v "$RPM_DIR:/packages:ro" \
    "$IMAGE_NAME" \
    bash /workspace/tests/integration/packaging/alt-clean-runtime-install-test.sh \
        /workspace /packages
