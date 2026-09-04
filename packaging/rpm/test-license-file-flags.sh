#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-fic-rpm-license-flags-test:fedora42}"
CONTAINER_CMD="${CONTAINER_CMD:-podman}"

"$CONTAINER_CMD" build \
    -t "$IMAGE_NAME" \
    -f "$ROOT_DIR/packaging/rpm/Dockerfile.license-flags-test" \
    "$ROOT_DIR"

"$CONTAINER_CMD" run --rm \
    -e FIC_DISPOSABLE_RPM_TEST=1 \
    -v "$ROOT_DIR:/workspace:ro" \
    "$IMAGE_NAME" \
    bash /workspace/tests/integration/packaging/rpm-license-file-flags-test.sh \
        /workspace
