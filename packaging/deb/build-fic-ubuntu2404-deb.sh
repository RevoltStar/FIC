#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

export FIC_PACKAGING_TARGET_PLATFORM="ubuntu-24.04"
export PACKAGE_DISTRO_TAG="ubuntu2404"
export BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/build-ubuntu2404}"

exec "$SCRIPT_DIR/build-fic-debian12-deb.sh" "$@"
