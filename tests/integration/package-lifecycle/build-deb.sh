#!/usr/bin/env bash
# Run inside a distro build container with /src readonly and /build writable.
# Uses the actual production staging/control/script generators, not dummy DEBs.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: build-deb.sh PLATFORM PRODUCT_VERSION' >&2; exit 2; }
export FIC_PACKAGING_TARGET_PLATFORM=$1 BUILD_ROOT=/build DIST_DIR=${DIST_DIR:-/build/lifecycle-packages}
version=$2
cmake -S /src -B /build -DFIC_TARGET_PLATFORM="$1" -DFIC_PRODUCT_VERSION="$version" \
    -DFIC_BUILD_COMMIT=unknown -DFIC_RELEASE_TAG=none -DFIC_RELEASE_BUILD=OFF
cmake --build /build --target fic fic-cli fic-dick fic-package-infrastructure pam_fic_access -j2
source /src/packaging/deb/build-fic-debian12-deb.sh "$version"
mkdir -p "$DIST_DIR"
verify_built_binary "$FIC_BUILD_DIR/fic" fic
verify_built_binary "$FIC_DICK_BUILD_DIR/fic-dick" fic-dick
verify_built_binary "$FIC_CLI_BUILD_DIR/fic-cli" fic-cli
build_fic_dick_package
build_fic_package
build_fic_cli_package
