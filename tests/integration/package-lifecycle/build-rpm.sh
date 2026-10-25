#!/usr/bin/env bash
# Actual production RPM staging, using the full-project native ALT build cache.
set -euo pipefail
[[ $# == 1 ]] || { echo 'usage: build-rpm.sh VERSION' >&2; exit 2; }
version=$1
export BUILD_ROOT=/build DIST_DIR=/build/lifecycle-packages
cmake -S /src -B /build -DFIC_TARGET_PLATFORM=alt-p11 -DFIC_PRODUCT_VERSION="$version" \
    -DFIC_BUILD_COMMIT=unknown -DFIC_RELEASE_TAG=none -DFIC_RELEASE_BUILD=OFF
cmake --build /build --target fic fic-cli fic-dick fic-package-infrastructure pam_fic_access pam_fic_pwtxn -j2
source /src/packaging/rpm/build-fic-alt-p11-rpm.sh "$version"
mkdir -p "$DIST_DIR"
init_rpm_tree
verify_built_binary "$FIC_BUILD_DIR/fic" fic
verify_built_binary "$FIC_DICK_BUILD_DIR/fic-dick" fic-dick
verify_built_binary "$FIC_CLI_BUILD_DIR/fic-cli" fic-cli
build_fic_dick_package
build_fic_package
build_fic_cli_package
