# Current workspace

## Current base / task
* Branch main; base `21da7cb6e87075cd19b89458225798d0519ee262`.
* pam_configuration_tests ModuleArguments fixture fix completed; separate
  thematic commit is HEAD, no push. Previous CI fixes remain unchanged.

## Accepted contract / completed
* Test helper verifyCapability prepares external config files and appends conf=
  only for ProviderConfigFile. ModuleArguments reaches the real verifier without
  either fixture mutation, matching existing production backend selection.
* Legacy pwhistory test keeps configPath in TempDirectory instead of /etc/security.
  Regression asserts absent config file and byte-identical PAM stack before/after
  verification (native remember=10, remember=0 ineffective, Structural acceptance).
* ModuleArguments backend priority test also retains its temporary configPath;
  existing provider-file content must not override explicit argv remember=7.
* No production, packaging, CMake, labels, CI filters, assertions or privilege
  changes. No sudo, extra capabilities, host policy apply or host system writes.

## Changed areas
* tests/fic/modules/identity_access/pam/PamConfigurationTests.cpp.
* This required AGENTS.md handoff snapshot.

## Validation (actually executed)
* Rootless Podman remote unix:///run/user/678421280/podman/podman.sock;
  fic-gui-dependency-tests:debian12; --userns keep-id --network none --cap-drop ALL
  --security-opt no-new-privileges, ordinary UID678421280; /src read-only.
* RED regression before helper fix: cmake --build /build --target
  pam_configuration_tests -j2 PASS; ctest --test-dir /build -R
  '^pam_configuration_tests$' --output-on-failure exit8,1 FAIL:
  `ModuleArguments verification created a provider config file`.
* GREEN same build/test commands: exit0,1 PASS/0 FAIL/0 SKIP.
* Normal /build = build-gui-dependencies, Debian12 target:
  FIC_BUILD_DIR=/build scripts/run-development-checks.sh full:
  full build exit0; CTest exit0,217 PASS/0 FAIL/10 SKIP (227 selected),74.51s.
* Sanitizer /build = build-ci-sanitizers, existing Ubuntu24.04 target Debug build:
  -fsanitize=address,undefined -fno-omit-frame-pointer, executable/shared linker
  flags -fsanitize=address,undefined. cmake --build /build --target
  pam_configuration_tests -j2 exit0.
  ASAN_OPTIONS=detect_leaks=1:halt_on_error=1,
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1;
  ctest --test-dir /build -L '^unit$' -LE '^root$' --output-on-failure:
  exit0,94 PASS/0 FAIL/1 SKIP (95 selected),56.17s; no sanitizer diagnostics.
* Logs: build-gui-dependencies/pam-fixture-{red-build,red-tests,green-build,
  green-tests,full}.log; build-ci-sanitizers/pam-fixture-{build,unit-tests}.log.
* Final diff review and git diff --check PASS. Only the test and this snapshot changed.

## Remaining / limits
* Full run10 skips: daemon_instance_lock_tests, daemon_singleton_startup_native,
  maintenance_preflight_native, package_writer_processes_tests,
  package_pam_hooks_tests, uninstall_lifecycle_tests, uninstall_override_tests,
  package_state_store_tests, sssd_uninstall_inspection_tests, sssd_proven_removal_tests.
  Sanitizer skip: sssd_proven_removal_tests. Root-only unit tests intentionally
  excluded by existing CI filter; native/root integration not proved here.
* Debian12/GCC12/Qt6.4 container differs from hosted Ubuntu24.04 runner. GitHub
  Actions not rerun. Full sanitizer all-target build/compiler-warnings not rerun;
  all selected unit binaries already built in previous task, changed target rebuilt.
