# Current workspace

## Current base
* Branch `main`; task base `9b86a21143feef13882b7b3c4a8ac44dec28ae0c`.

## Current task
* Fix Display Manager inventory treating uninstantiated systemd service templates
  as concrete units. Implementation and mandatory Docker regression tests complete;
  one commit requested, no push.

## Accepted architecture / invariants
* Only valid `prefix@.service` names from list-unit-files are excluded from the
  set queried with systemctl show. Prefix must be nonempty, contain documented
  systemd unit-name characters and no other @; total name length <=255.
* Existing service identity guard runs before exclusion. Invalid lookalikes keep
  the original validation/show error path. Concrete instances from either source
  remain subject to all existing property/executable/configuration checks.
* list-units merging, unknown DM detection, fail-closed errors and executable trust
  are unchanged. No GUI/IPC/planner/dependency/ownership/rollback changes.
* Official references checked: systemctl and systemd.unit man pages at
  https://www.freedesktop.org/software/systemd/man/latest/ . No existing reusable
  template recognizer found; service activation name validator has a different,
  restricted contract and was not reused.

## Completed / changed areas
* Local template recognizer and one filter in DisplayManagerInventory.cpp.
* Existing DisplayManagerTransactionTests.cpp Run fixture extended with A-F:
  original template failure, instances from each source/union, custom instance
  invoking SDDM, unknown active DM, concrete show/property failures, template-only
  headless inventory. Also checks malformed lookalikes and custom config rejection.
* No other implementation areas changed.

## Validation
* Docker CLI through existing rootless Podman API:
  unix:///run/user/678421280/podman/podman.sock . Existing Debian12 image
  fic-gui-dependency-tests:debian12; source /src RO, build directory /build RW,
  network none, no-new-privileges, cap-drop ALL with only
  CHOWN/FOWNER/SETUID/SETGID/KILL added for existing filesystem fixtures.
* RED: new regression + original production code. Build target
  display_manager_transaction_tests exit0; CTest exit8 with
  "DM inventory command failed: injected systemctl show refusal: alsa-card-wait@.service".
* GREEN: cmake --build /build --target fic display_manager_transaction_tests
  policy_save_dependency_tests -j2 exit0. Final CTest exit0, **6/6 PASS**:
  display_manager_transaction_tests, policy_save_dependency_tests,
  policy_execution_planner_tests, desktop_package_release_checks,
  desktop_environment_architecture_static_checks, module_ui_static_checks.
* Evidence: build-gui-dependencies/dm-template-{red,green}-{build,tests}.log .
* Diff reviewed; git diff --check PASS.

## Remaining / limits
* No native systemd test: selected image has neither systemctl nor systemd manager
  (PID1 is sh). Mandatory deterministic regressions were actually run in Docker.
* No host services/config changes, no production computers or 192.168.1.50 used.
  This does not establish successful policy apply all on a real installation.
* Full project CTest not rerun for this local change. Previous task's known broad
  failures (not changed here): incident_state_lifecycle_static_checks (RPM manifest,
  reproduced on that task's base) and identity_policy_hierarchy_tests (PAM
  recommendation assertion). Previous full run: 225 PASS /4 SKIP /2 FAIL.
