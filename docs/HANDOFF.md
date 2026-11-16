# Current workspace

## Current base
* Branch `main`; task base `30d600508b26fc0b63504e48b74a46f466f1ed73`.

## Current task
* Dependency-aware fic-gui saving implemented and validated; one commit, no push.

## Accepted architecture / invariants
* Existing individual mutation commands, immediate daemon reconciliation and
  PolicyExecutionPlanner semantics remain. No batch API, transaction, rollback,
  auto-enabling dependencies or repair of inconsistent starting configurations.
* Additive `policy_list.dependencies` describes all declared Required/Recommended
  edges even for disabled owners. Existing `required_dependencies` is preserved.
  Daemon evaluates current applicability/backend capabilities; GUI reevaluates
  OwnerValueEquals against edited target values. See GUI section in
  `docs/architecture-diagrams.md` for wire fields and ordering contract.
* Both save paths share one operation plan. Fresh metadata precedes mutations;
  stable topological order prefers disable, settings, enable, subject to required
  dependency constraints. Recommendations never introduce a planning failure.
  First command failure stops the plan; already saved changes remain saved.

## Completed / changed areas
* Daemon policy JSON metadata; GUI descriptor parser and PolicyService planner.
* Regression tests use actual DE/DM policy constructors, daemon JSON, GUI parsing,
  real dependency planner/reverse disable guard, temporary configuration, and
  stubbed own OS apply. Test daemon and GUI translation units stay separate
  because their existing ModuleView types have the same name.
* Coverage includes DE/DM enable/disable, value-before-enable, disable-before-scope
  change, chains, recommendations, stable independent changes, conditional target
  values/backend applicability, both save paths and stop-on-error behavior.

## Validation
* Docker CLI via rootless Podman Docker-compatible API; Debian12 image built
  using `packaging/deb/Dockerfile` (legacy Docker build API after BuildKit DNS
  failure). Runtime: no network, no-new-privileges, source RO, only build directory
  mounted RW. Final CTest caps: CHOWN/FOWNER/SETUID/SETGID/KILL; no DAC_OVERRIDE
  (it defeats chmod-based write-failure injection). No production machine or
  192.168.1.50 used.
* `cmake -S /src -B /build -DFIC_TARGET_PLATFORM=debian-12` PASS.
* Targeted build and CTest: module_registry_tests, policy_execution_planner_tests,
  policy_descriptor_tests, policy_service_tests, policy_save_dependency_tests:
  **5/5 PASS**. Initial test-only ModuleView collision corrected by splitting TUs.
* `python3 tests/fic-gui/policies/static_checks.py .` PASS.
* Docker `cmake --build /build -j4` PASS (full project, all targets).
* Docker module_ui_static_checks and two offscreen policy editor tests: 3/3 PASS.
* Final Docker `ctest --test-dir /build --output-on-failure`: **225 PASS / 4 SKIP /
  2 FAIL**. All changed-area tests PASS. Final log:
  `build-gui-dependencies/final-no-dac-tests.log`; configure/build/targeted/editor
  logs in the same directory. Initial no-capability run had ownership/UID fixture
  failures; rechecked with required caps. Intermediate DAC_OVERRIDE run bypassed
  mutation_journal_tests permission fault; final run without it passes that test.
* Final diff review and `git diff --check` PASS.

## Remaining / limits
* Unrelated full-suite failures left unchanged:
  - incident_state_lifecycle_static_checks: RPM manifest assertion. Reproduced
    with archived task-base files; `baseline-static-test.log`.
  - identity_policy_hierarchy_tests: PAM capability activation recommendations.
    None of its 329 source/header build dependencies changed in this task;
    `identity-unchanged-dependencies.log`. No separate baseline rebuild claimed.
* Four native tests skipped: verified_config_service_native_tests,
  daemon_singleton_startup_native, maintenance_preflight_native,
  package_pam_hooks_native (container/native prerequisites unavailable).
* Backend metadata is a snapshot; concurrent changes/real apply failures are still
  checked by daemon per command. No real graphical session/native DE/DM apply or
  package-manager E2E is part of this regression fixture.
