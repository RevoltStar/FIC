#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: run-i3.sh TAG PLATFORM BUILD_DIR'; exit 2; }
tag=$1 platform=$2 build=$(realpath "$3")
case "$tag:$platform" in debian12:debian-12|debian13:debian-13|ubuntu2404:ubuntu-24.04|ubuntu2604:ubuntu-26.04|alt-p11:alt-p11) ;; *) exit 2;; esac
image="fic-package-native:$tag"
if [[ $tag == alt-p11 ]]; then image=fic-pam-dependencies-native:alt-p11; fi
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
out="$repo/build-pam-r1-i3"; mkdir -p "$out"
# A failed build must never leave this invocation looking like an older PASS.
: > "$out/i3-tests-$tag.log"
rm -f "$out/i3-contracts-$tag.json" "$out/i3-audit-$tag.json"
targets='pam_dependency_contract_tests pam_configuration_tests pam_capability_activation_policy_tests pam_password_wiring_tests policy_execution_planner_tests pam_provider_rollback_tests pam_provider_package_release_tests pam_provider_managed_entry_executor_tests pam_provider_managed_flag_executor_tests rollback_executor_tests'
docker run --rm --network none \
 -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
 -v "$repo:/src:ro" -v "$build:/build" "$image" sh -ec '
 cmake -S /src -B /build -DFIC_TARGET_PLATFORM="$1"
 cmake --build /build --target fic $2 -j2
 ' sh "$platform" "$targets" > "$out/i3-build-$tag.log" 2>&1
# The host owns the build directory. Prepare only generated CTest outputs
# while DAC_OVERRIDE is available; runtime fault tests below must lack it.
docker run --rm --network none -v "$build:/build" "$image" sh -ec '
 mkdir -p /build/Testing/Temporary
 touch /build/pam-i3-contracts.json /build/pam-i3-audit.json
 chown 0:0 /build/Testing /build/Testing/Temporary /build/pam-i3-contracts.json /build/pam-i3-audit.json
 '
# Permission-negative fixtures require root without DAC override; no host
# security state is mounted writable, and all tests use temporary fixtures.
docker run --rm --network none --cap-drop DAC_OVERRIDE --cap-drop DAC_READ_SEARCH \
 -v "$repo:/src:ro" -v "$build:/build" "$image" sh -ec '
 ctest --test-dir /build -R "^(pam_dependency_contract_tests|pam_configuration_tests|pam_capability_activation_policy_tests|pam_password_wiring_tests|policy_execution_planner_tests|pam_provider_rollback_tests|pam_provider_package_release_tests|pam_provider_managed_entry_executor_tests|pam_provider_managed_flag_executor_tests|rollback_executor_tests|pam_packaging_static_checks|platform_profile_static_checks)$" --output-on-failure
 /build/tests/pam_dependency_contract_tests --audit /build/pam-i3-audit.json
 ' > "$out/i3-tests-$tag.log" 2>&1
cp "$build/pam-i3-contracts.json" "$out/i3-contracts-$tag.json"
cp "$build/pam-i3-audit.json" "$out/i3-audit-$tag.json"
