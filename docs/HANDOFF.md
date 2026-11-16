# Current workspace

## Current base / task
* Branch main; two-fix task base `3eab56df5aa8391cbd6641b5e160658fc25c2d2f`.
* Sequential work: commit1 logind inventory complete; commit2 prelogin D-Bus
  diagnostics/Unavailable visual semantics remains. No push, no production tests.

## Accepted invariants / completed
* show-session now uses separate --property=Class and --property=Service.
  Nonempty Class required for every session; nonempty Service required only for
  greeter. Unknown greeter, command errors and empty session-list behavior retained.
* Existing systemctl/template inventory, executable trust, ownership, rollback,
  policy planner and dependency graph unchanged.
* Production/test changes only DisplayManagerInventory.cpp and existing
  DisplayManagerTransactionTests.cpp (inventoryLogindProof A-H, exact arguments,
  absent/empty fields, known/unknown greeters, command errors, no sessions).
* Official loginctl documentation checked: repeated --property selects multiple
  properties; empty properties are suppressed without --all. No --all needed:
  missing required fields and explicit empty required fields both fail closed.

## Validation (Docker, actually executed)
* Docker CLI -H unix:///run/user/678421280/podman/podman.sock (rootless Podman API),
  image fic-gui-dependency-tests:debian12, /src RO, /build RW, network none,
  no-new-privileges; cap-drop ALL + CHOWN/FOWNER/SETUID/SETGID/KILL for fixtures.
* RED build display_manager_transaction_tests exit0; CTest exit8 rejecting old
  --property=Class,Service. Logs build-gui-dependencies/logind-red-{build,tests}.log.
* GREEN cmake --build /build --target fic display_manager_transaction_tests
  policy_save_dependency_tests -j2 exit0; CTest regex selected
  display_manager_transaction_tests, policy_save_dependency_tests,
  policy_execution_planner_tests, desktop_package_release_checks,
  desktop_environment_architecture_static_checks: **5 PASS /0 FAIL /0 SKIP**, exit0.
  Logs build-gui-dependencies/logind-green-{build,tests}.log.
* Diff review and git diff --check PASS.

## Remaining / limits
* Next: inspect prelogin observer/provider/controller/view, add bounded per-call
  sd-bus diagnostics without changing250ms timeout or retries. Unavailable must
  be warning/unconfirmed, never startup failure/success. Preserve all freshness,
  boot/PID/IPC peer/access-gate/renderer/countdown/manual/recovery invariants.
* No real host apply all or native logind test. Test image lacks systemd manager.
* Full CTest not rerun for the local inventory change. Previously known unrelated
  broad failures: incident_state_lifecycle_static_checks and
  identity_policy_hierarchy_tests (previous225 PASS /4 SKIP /2 FAIL).
