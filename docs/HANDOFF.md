# Current workspace

## Current base / task
* Branch main; base `45d0f8752450167c572e10121301b56c4d7d1165`.
* Three stale CI/test expectations from Actions run 43911571313 fixed in one
  thematic commit (HEAD); no push. Production behavior/root classification unchanged.

## Accepted contract / completed
* RPM write_file_list already emits `%dir %attr(2750,root,fic) /opt/fic/bin`
  (27f97439). Lifecycle check now verifies those exact attributes and uniqueness,
  retains fic, rejects ownership of /opt/fic and /opt/fic/config with any attributes.
* PamOptionPolicy already adds Required activation dependencies for every support
  state except Unsupported (8ae2ebb8). Hierarchy test checks exact PolicyRefs,
  all four lockout options/history, ReadOnly pwquality and static Supported
  pwquality, absent capability and provider-binding mismatch. Exact dependency
  counts reject duplicates; disable_nopasswdlogin remains Recommended.
* Sanitizer job keeps ASan/UBSan flags/options, adds `-LE '^root$'` to `-L '^unit$'`.
  DM geteuid guard and `unit;root` labels unchanged; no sudo/privileged CI containers.

## Changed areas
* .github/workflows/ci.yml; IncidentStateLifecycleChecks.py;
  IdentityPolicyHierarchyTests.cpp. This required AGENTS.md handoff snapshot.
* No production sources, packaging generators or tests/CMakeLists.txt changes.

## Validation (actually executed)
* GitHub API job/log inspection confirms original 2/227 build and 2/97 sanitizer
  failures; compiler-warnings passed. History/current sources inspected before edits.
* Docker/Podman rootless socket unix:///run/user/678421280/podman/podman.sock;
  fic-gui-dependency-tests:debian12, --network none --cap-drop ALL
  --security-opt no-new-privileges; /src read-only. No host policy/system mutation.
* RED: ctest --test-dir /build -R
  '^(incident_state_lifecycle_static_checks|identity_policy_hierarchy_tests)$'
  --output-on-failure: 2 FAIL with original diagnostics. DM binary under UID65534
  rejects with original disposable-root requirement (exit1).
* GREEN: cmake --build /build --target identity_policy_hierarchy_tests
  pam_dependency_contract_tests -j2; ctest --test-dir /build -R
  '^(incident_state_lifecycle_static_checks|identity_policy_hierarchy_tests|private_client_permissions_tests|pam_dependency_contract_tests)$'
  --output-on-failure: 4 PASS,0 FAIL,0 SKIP. /build = build-gui-dependencies.
* ctest -N -L '^unit$' versus -L '^unit$' -LE '^root$' (JSON set comparison):
  97 ->95, excludes exactly display_manager_transaction_tests and
  device_startup_readiness_tests. Every other unit test retained. YAML parsed;
  sanitizer options/command asserted. Actual full run also excludes both tests.
* Six in-memory RPM generator mutations rejected: either protected parent owned,
  wrong bin mode/owner/group, omitted daemon. No production files modified.
* FIC_BUILD_DIR=/build scripts/run-development-checks.sh full, non-root keep-id:
  full build exit0; CTest exit8,216 PASS/1 FAIL/10 SKIP (227 selected),81.10s.
  Failure pam_configuration_tests: `could not write /etc/security/pwhistory.conf`.
  Existing verifyCapability helper creates missing configPath; Debian12 image
  lacks native file. This test passed in original Ubuntu24.04 Actions log.
* Earlier UID0/cap-drop-ALL full run: exit8,216 PASS/9 FAIL/2 SKIP; root-only
  ownership/credential fixture branches cannot run without capabilities. Retried
  under ordinary UID via Podman --userns keep-id, without granting capabilities.
* Logs: build-gui-dependencies/ci-infrastructure-{focused-build,focused-tests,full,full-nonroot}.log.
* Sanitizer configure, /build = build-ci-sanitizers:
  cmake -S . -B /build -DFIC_TARGET_PLATFORM=ubuntu-24.04 -DCMAKE_BUILD_TYPE=Debug
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
  -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address,undefined': exit0.
* Built all88 binary targets for the selected95 unit tests (+7 Python checks),
  using xargs cmake --build /build --parallel 2 --target < /targets: exit0.
  Target list derived from CTest commands; initially used test name instead of
  pam_native_consumer_probe target, then resumed with corrected list. Optional
  full sanitizer all-target build stopped in favor of unit targets, not completed.
* keep-id/non-root, ASAN_OPTIONS=detect_leaks=1:halt_on_error=1,
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1;
  ctest --test-dir /build -N -L '^unit$' -LE '^root$': exactly95 selected.
  ctest --test-dir /build -L '^unit$' -LE '^root$' --output-on-failure:
  exit8,93 PASS/1 FAIL/1 SKIP,66.00s. No ASan/UBSan diagnostics. Only failure:
  same pam_configuration_tests native-file fixture; skip sssd_proven_removal_tests.
  identity_policy_hierarchy_tests and pam_dependency_contract_tests PASS.
* Sanitizer logs: build-ci-sanitizers/{configure,unit-build,unit-build-resumed,
  selected-tests,focused-tests,unit-tests}.log. Final diff review/diff --check PASS.

## Remaining / limits
* Local container Debian12/GCC12/Qt6.4 differs from hosted Ubuntu24.04 runner;
  normal build target Debian12, sanitizer target Ubuntu24.04. No full all-target
  sanitizer build or compiler-warnings job rerun (no production changes).
* pam_configuration_tests native-file fixture failure outside requested scope;
  do not silently fix or grant permissions to hide it. Native/root skips remain.
  Full run10 skips: daemon_instance_lock_tests, daemon_singleton_startup_native,
  maintenance_preflight_native, package_writer_processes_tests,
  package_pam_hooks_tests, uninstall_lifecycle_tests, uninstall_override_tests,
  package_state_store_tests, sssd_uninstall_inspection_tests, sssd_proven_removal_tests.
* GitHub Actions has not been rerun; no claim of a fully green hosted pipeline.
