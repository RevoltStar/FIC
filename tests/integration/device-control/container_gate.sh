#!/usr/bin/env bash
# Disposable Docker only. Uses no writable host sysfs mount.
set -euo pipefail
[[ -f /.dockerenv && $(id -u) = 0 ]] || { echo 'Disposable root Docker container required' >&2; exit 97; }
REPO=${REPO:-/src}
BUILD=${BUILD:-/build}
PLATFORM=${PLATFORM:?}
mkdir -p "$BUILD"
trap 'rc=$?; tail -35 "$BUILD/dc-build.log" "$BUILD/dc-tests.log" "$BUILD/dc-ipc.log" 2>/dev/null || true; exit "$rc"' ERR
cmake -S "$REPO" -B "$BUILD" -DFIC_TARGET_PLATFORM="$PLATFORM" > "$BUILD/dc-configure.log" 2>&1
cmake --build "$BUILD" --target fic fic-dick fic-cli device_category_policy_tests device_tree_snapshot_tests device_tree_revision_tests device_policy_compiler_tests device_enforcer_tests device_audit_tests device_incident_event_tests rollback_executor_tests schema_contract_tests -j3 > "$BUILD/dc-build.log" 2>&1
ctest --test-dir "$BUILD" -R '^(device_category_policy_tests|device_tree_snapshot_tests|device_tree_revision_tests|device_policy_compiler_tests|device_enforcer_tests|device_audit_tests|device_incident_event_tests|rollback_executor_tests|schema_contract_tests|device_control_static_checks)$' --output-on-failure > "$BUILD/dc-tests.log" 2>&1
python3 "$REPO/tests/integration/device-control/category_ipc_gate.py" "$BUILD" "$REPO" > "$BUILD/dc-ipc.log" 2>&1
cat "$BUILD/dc-tests.log" "$BUILD/dc-ipc.log"
