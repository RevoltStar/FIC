#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "$ROOT_DIR/packaging/lib/version-contract.sh"

fail() {
    echo "version-contract-test: $1" >&2
    exit 1
}

fic_configure_product_version 0.0.0
[ "$FIC_PRODUCT_VERSION" = "0.0.0" ] || fail "stable product version changed"
[ "$FIC_PACKAGE_VERSION" = "0.0.0" ] || fail "stable package version changed"

fic_configure_product_version 0.1.0-rc.1
[ "$FIC_PRODUCT_VERSION" = "0.1.0-rc.1" ] || fail "prerelease product version changed"
[ "$FIC_PACKAGE_VERSION" = "0.1.0~rc.1" ] || fail "prerelease package ordering is wrong"

for invalid in 0.0 00.0.0 0.1.0-rc.01 0.0.0+local v0.1.0; do
    if (fic_configure_product_version "$invalid" >/dev/null 2>&1); then
        fail "accepted invalid product version '$invalid'"
    fi
done
if (fic_configure_product_version >/dev/null 2>&1); then
    fail "accepted an omitted product version"
fi

TEMP_DIR="$(mktemp -d /tmp/fic-version-cmake-test-XXXXXX)"
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

cmake -S "$ROOT_DIR/fic-common/fic-version" -B "$TEMP_DIR/valid" \
    -DFIC_PRODUCT_VERSION=0.1.0-rc.1 \
    -DFIC_RELEASE_BUILD=ON \
    -DFIC_RELEASE_TAG=v0.1.0-rc.1 \
    -DFIC_BUILD_COMMIT=0123456789abcdef0123456789abcdef01234567 >/dev/null
VALID_HEADER="$TEMP_DIR/valid/generated/include/fic/version/ProductVersion.h"
grep -Fq 'PRODUCT_VERSION = "0.1.0-rc.1"' "$VALID_HEADER" ||
    fail "CMake generated the wrong product version"
grep -Fq 'BUILD_KIND = "release"' "$VALID_HEADER" ||
    fail "CMake did not mark the release build"
grep -Fq 'RELEASE_TAG = "v0.1.0-rc.1"' "$VALID_HEADER" ||
    fail "CMake generated the wrong release tag"

if cmake -S "$ROOT_DIR/fic-common/fic-version" -B "$TEMP_DIR/tag-mismatch" \
    -DFIC_PRODUCT_VERSION=0.1.0 \
    -DFIC_RELEASE_BUILD=ON \
    -DFIC_RELEASE_TAG=v0.1.1 \
    -DFIC_BUILD_COMMIT=0123456789abcdef0123456789abcdef01234567 \
    >/dev/null 2>&1; then
    fail "CMake accepted a release tag/version mismatch"
fi

if cmake -S "$ROOT_DIR/fic-common/fic-version" -B "$TEMP_DIR/short-sha" \
    -DFIC_BUILD_COMMIT=0123456 >/dev/null 2>&1; then
    fail "CMake accepted an abbreviated commit"
fi
