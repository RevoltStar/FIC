#!/usr/bin/env bash
# Fixed I1/I2/I4/I5/I6 native build + fixture regressions; never apply policies to the host.
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: run-i1.sh TAG PLATFORM BUILD_DIR'; exit 2; }
tag=$1 platform=$2
case "$tag:$platform" in debian12:debian-12|debian13:debian-13|ubuntu2404:ubuntu-24.04|ubuntu2604:ubuntu-26.04|alt-p11:alt-p11) ;; *) exit 2;; esac
mkdir -p "$3"
build=$(realpath "$3")
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
stage=${FIC_PAM_GATE_STAGE:-i1}
case "$stage" in i1|i2|i4|i5|i6) ;; *) exit 2;; esac
out="$repo/build-pam-$stage"; mkdir -p "$out"
image="fic-package-native:$tag"
if [[ $tag == alt-p11 ]]; then image=fic-pam-dependencies-native:alt-p11; fi
targets='pam_dependency_contract_tests pam_configuration_tests pam_control_flow_analyzer_tests pam_auth_update_topology_tests pam_capability_activation_policy_tests pam_password_wiring_tests policy_execution_planner_tests pam_provider_rollback_tests pam_provider_package_release_tests pam_provider_managed_entry_executor_tests pam_provider_managed_flag_executor_tests rollback_executor_tests alt_pam_faillock_topology_tests alt_pam_password_history_topology_tests pam_managed_password_slots_tests pam_managed_password_slot_writer_tests pam_password_topology_model_tests pam_password_topology_planner_tests pam_password_topology_executor_tests pam_password_package_release_tests'
if [[ $stage == i4 || $stage == i5 || $stage == i6 ]]; then
 targets+=' pam_provider_managed_block_tests pam_provider_managed_block_file_tests'
fi
if [[ ( $stage == i5 || $stage == i6 ) && $tag == alt-p11 ]]; then
 targets+=' pam_fic_pwtxn'
fi
if [[ $stage == i6 ]]; then targets+=' pam_native_consumer_probe'; fi
extra=''
if [[ $stage == i6 ]]; then extra='|pam_native_consumer_conversation_tests'; fi
regex="^($(tr ' ' '|' <<< "$targets")|pam_packaging_static_checks|platform_profile_static_checks${extra})$"
# Source receipt excludes docs/evidence, so later reporting cannot change it.
receipt() {
 python3 - "$repo" <<'PY'
import hashlib,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]); h=hashlib.sha256()
paths=subprocess.check_output(['git','-C',str(root),'ls-files','-z','fic','fic-common','tests','cmake','CMakeLists.txt']).decode().split('\0')
for name in sorted(p for p in paths if p and pathlib.Path(p).suffix in {'.cpp','.h','.c','.cmake','.txt','.py','.sh'}):
 h.update(name.encode()+b'\0'+hashlib.sha256((root/name).read_bytes()).digest())
print(h.hexdigest())
PY
}
receipt > "$out/$stage-source-$tag.before"
: > "$out/$stage-tests-$tag.log"
docker image inspect "$image" --format '{{json .Id}}' > "$out/$stage-image-$tag.json"
docker run --rm --network none \
 -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
 -v "$repo:/src:ro" -v "$build:/build" "$image" sh -ec '
 cmake -S /src -B /build -DFIC_TARGET_PLATFORM="$1"
 cmake --build /build --target fic $2 -j6
 mkdir -p /build/Testing/Temporary
 touch /build/pam-i3-contracts.json /build/pam-i1-audit.json
 chown 0:0 /build/Testing /build/Testing/Temporary /build/pam-i3-contracts.json /build/pam-i1-audit.json
 ' sh "$platform" "$targets" > "$out/$stage-build-$tag.log" 2>&1
docker run --rm --network none --cap-drop DAC_OVERRIDE --cap-drop DAC_READ_SEARCH \
 -v "$repo:/src:ro" -v "$build:/build" "$image" sh -ec '
 ctest --test-dir /build -R "$1" --output-on-failure
 /build/tests/pam_dependency_contract_tests --audit /build/pam-i1-audit.json
 cat /etc/os-release
 if command -v rpm >/dev/null; then rpm -q cmake ctest gcc-c++ libpam0-devel; else dpkg-query -W cmake g++ libpam0g libpam-runtime; fi
 ' sh "$regex" > "$out/$stage-tests-$tag.log" 2>&1
receipt > "$out/$stage-source-$tag.after"
cmp "$out/$stage-source-$tag.before" "$out/$stage-source-$tag.after"
cp "$build/pam-i3-contracts.json" "$out/$stage-contracts-$tag.json"
cp "$build/pam-i1-audit.json" "$out/$stage-audit-$tag.json"
sha256sum "$build/fic/fic" "$build/tests/pam_dependency_contract_tests" > "$out/$stage-binaries-$tag.sha256"
