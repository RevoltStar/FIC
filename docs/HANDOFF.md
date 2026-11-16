# Current workspace

## Current base / task
* Branch main; follow-up base `3e28cc1279ac79fb30b72ae1f198dd3f4f0e8269`.
* Current task complete: distinguish confirmed systemd service failure and persist
  D-Bus observation diagnostics. One follow-up commit (HEAD); no push.

## Accepted invariants / completed
* Successful systemd observation ActiveState=failed without verified IPC selects
  ServiceFailed / DAEMON_SERVICE_FAILED. Qt first step Failed/red error banner,
  remaining steps Waiting. Does not assert apply failure.
* Verified IPC retains priority: STARTUP_FAILED is first-apply failure (second step
  Failed); DAEMON_DEGRADED stays distinct. DAEMON_UNAVAILABLE is missing/incomplete
  observation, Warning first step/banner. See fic-prelogin/README.md.
* Broker records SystemdStatus.error via stderr (unit StandardError=journal).
  PreLoginObservationLog suppresses identical current errors; changed reason logs
  immediately; successful observation clears suppression. Missing IPC alone never
  generates a D-Bus record. Existing sanitized <=1024-byte diagnostics unchanged.
  Console keeps full TTY diagnostics; during D-Bus failure stdout emits only state
  to avoid duplicate journal diagnostics. Qt does not log observation errors.
* No changes to prelogin_status IPC, sd-bus algorithm/250ms timeout/poll interval,
  boot/PID/peer validation, mayAutoHandoff, login/access/renderer proofs, full 5s
  countdown, manual/power/recovery/resource cleanup/cgroup proof. Verified fresh
  IPC remains necessary for auto-handoff; missing proof resets countdown.

## Changed areas
* fic-prelogin/src/PreLoginController.*, PreLoginObservationLog.h, main.cpp,
  QtPreLoginView.cpp; fic-prelogin/README.md; three incident prelogin test files.

## Validation (Docker, actually executed)
* Docker CLI -H unix:///run/user/678421280/podman/podman.sock, image
  fic-gui-dependency-tests:debian12. run --rm --network none --cap-drop ALL
  --cap-add CHOWN --cap-add FOWNER --cap-add SETUID --cap-add SETGID --cap-add KILL
  --security-opt no-new-privileges; repository mounted /src:ro, existing
  build-gui-dependencies mounted /build:rw; workdir /src.
* RED: cmake --build /build --target prelogin_controller_tests prelogin_qt_view_tests
  -j2 (exit0); ctest --test-dir /build -R
  '^(prelogin_controller_tests|prelogin_qt_view_tests)$' --output-on-failure
  (exit8; 0 PASS /2 FAIL /0 SKIP). Controller classification and Qt token fail.
* GREEN: cmake --build /build --target fic-prelogin fic-prelogin-frontend
  fic-prelogin-integration prelogin_daemon_fixture prelogin_controller_tests
  prelogin_qt_view_tests prelogin_frontend_process_tests daemon_readiness_tests
  device_startup_readiness_tests incident_access_client_tests -j2 (exit0).
* ctest --test-dir /build -R
  '^(prelogin_controller_tests|prelogin_qt_view_tests|prelogin_frontend_process_tests|prelogin_package_lifecycle_tests|daemon_readiness_tests|device_startup_readiness_tests|incident_access_client_tests)$'
  --output-on-failure: exit0, **7 PASS /0 FAIL /0 SKIP**, 13.84s final run.
  Qt uses CTest property QT_QPA_PLATFORM=offscreen.
* Evidence: build-gui-dependencies/prelogin-followup-{red,green}-{build,tests}.log;
  Testing/Temporary/LastTest.log includes actual journal-channel regression PASS.
* Coverage: failed/unavailable/apply-failed/degraded distinction, Qt actual steps
  and banner colors, broker packet, IPC priority, countdown reset/restart,
  manual/power availability, channel write/flush counts and exact payload,
  changed cause/recovery, real private sd-bus errors and missing-IPC progress.
* Final diff review and git diff --check PASS.

## Remaining / limits
* No production computers or 192.168.1.50. No host policy apply, native systemd
  journal persistence/reboot, VT/DRM/DM E2E: container lacks systemd manager.
  Tested actual logging output channel plus existing unit stderr=journal wiring.
* Original transient D-Bus incident cause remains unknown; timeout not established
  as its cause. Full CTest not repeated for focused follow-up. Prior unrelated
  broad failures remain incident_state_lifecycle_static_checks and
  identity_policy_hierarchy_tests (previous225 PASS /4 SKIP /2 FAIL).
