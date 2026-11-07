#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: build-and-audit.sh TAG PLATFORM BUILD_DIR'; exit 2; }
tag=$1 platform=$2 build=$(realpath "$3")
case "$tag:$platform" in debian12:debian-12|debian13:debian-13|ubuntu2404:ubuntu-24.04|ubuntu2604:ubuntu-26.04|alt-p11:alt-p11) ;; *) exit 2;; esac
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
out="$repo/build-pam-r1-i3";mkdir -p "$out"
docker run --rm --network none \
 -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
 -v "$repo:/src:ro" -v "$build:/build" "fic-package-native:$tag" sh -ec '
 cmake -S /src -B /build -DFIC_TARGET_PLATFORM="$1"
 cmake --build /build --target pam_dependency_contract_tests -j2
 /build/tests/pam_dependency_contract_tests --audit /build/pam-r1-audit.json
 ' sh "$platform" > "$out/r1-audit-$tag.log" 2>&1
cp "$build/pam-r1-audit.json" "$out/audit-$platform.json"
