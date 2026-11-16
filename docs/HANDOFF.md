# Current workspace

## Current base / task
* Branch main; task base `3eab56df5aa8391cbd6641b5e160658fc25c2d2f`.
* Two sequential fixes complete. Commit1:
  `41a9e0c77732e284699fcbcfe7be67b261a79b0d`
  (`fix(oss): correct logind session property inventory`).
* Commit2 is HEAD: prelogin observation diagnostics / warning semantics. No push.

## Accepted invariants / completed
* DM show-session uses separate --property=Class and --property=Service.
  Nonempty Class is always required; nonempty Service is required only for greeter.
  Unknown greeters and command errors remain fail-closed. Template handling unchanged.
* Prelogin systemd observer reports operation/property/negative errno-style code,
  strerror and sd_bus_error name/message. Diagnostic <=1024 bytes, UTF-8 safe;
  no partial properties on failure. Provider preserves it ahead of missing-IPC error.
* One explicit bus-opening fixture seam; production endpoint/system bus unchanged.
  Tests use a private socketpair and actual sd-bus methods/errors, no host bus.
* DAEMON_UNAVAILABLE first step and banner are Warning: current startup/apply result
  unconfirmed. STARTUP_FAILED remains red; DEGRADED remains distinct. Authoritative
  semantics in fic-prelogin/README.md.
* No change to controller algorithm, mayAutoHandoff, boot/PID/IPC peer validation,
  completion/apply/access-gate/login requirements, renderer readiness,5s countdown,
  manual/power/recovery/cleanup/cgroup proof. Timeout250ms unchanged; no retries.
* sd-bus error and timeout APIs checked against official systemd documentation.

## Validation (Docker, actually executed)
* Docker CLI -H unix:///run/user/678421280/podman/podman.sock (rootless Podman API),
  image fic-gui-dependency-tests:debian12. /src RO, /build RW, network none,
  no-new-privileges; cap-drop ALL + CHOWN/FOWNER/SETUID/SETGID/KILL for fixtures.
* Commit1 RED build display_manager_transaction_tests exit0; CTest exit8 rejects old
  combined --property=Class,Service. GREEN build fic, display_manager_transaction_tests,
  policy_save_dependency_tests -j2 exit0. CTest **5 PASS /0 FAIL /0 SKIP**, exit0:
  display_manager_transaction_tests, policy_save_dependency_tests,
  policy_execution_planner_tests, desktop_package_release_checks,
  desktop_environment_architecture_static_checks. Evidence:
  build-gui-dependencies/logind-{red,green}-{build,tests}.log.
* Commit2 build fic-prelogin, fic-prelogin-frontend, prelogin_controller_tests,
  prelogin_qt_view_tests, prelogin_frontend_process_tests, daemon_readiness_tests,
  device_startup_readiness_tests, incident_access_client_tests -j2 exit0.
  Separate build fic-prelogin-integration and prelogin_daemon_fixture -j2 exit0.
* Commit2 CTest **7 PASS /0 FAIL /0 SKIP**, exit0: prelogin_controller_tests,
  prelogin_qt_view_tests (offscreen), prelogin_frontend_process_tests,
  prelogin_package_lifecycle_tests, daemon_readiness_tests,
  device_startup_readiness_tests, incident_access_client_tests. Evidence:
  build-gui-dependencies/prelogin-fix-{build,tests,consumers-build}.log.
* Regression coverage: logind A-H/exact arguments; D-Bus open/GetUnit/all4 properties/
  malformed reply/errno/text bounds/UTF-8; provider->Observation and broker packet;
  same-view Applying/Unavailable/Applying/Succeeded/Failed transitions; actual step
  states and warning/error banner; countdown reset/restart, boot/PID/peer checks,
  renderer barrier/manual actions and cleanup. Test stdout in Testing/Temporary/LastTest.log.
* Final diff review and git diff --check PASS.

## Remaining / limits
* No real host apply all, boot-timeout diagnosis, native logind/systemd/DRM/DM E2E.
  Test image lacks systemd manager. Original transient D-Bus failure cause still
  requires real-system evidence; do not claim timeout250ms was proven insufficient.
* No production computers /192.168.1.50 used. Full CTest not repeated: focused tests
  and all direct prelogin-core consumers were built/checked. Previously known unrelated
  broad failures remain: incident_state_lifecycle_static_checks and
  identity_policy_hierarchy_tests (previous225 PASS /4 SKIP /2 FAIL).
