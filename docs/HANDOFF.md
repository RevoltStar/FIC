# Current workspace

## Current base / task
* Branch `main`; base `ebce360f76dde65df3dbd44048dc6b9b40979ef4`.
* Follow-up: classify startup-gate-blocked DC as ExecutionInfrastructureFailure.
  Requested commit: `fix(startup): classify blocked device policies as infrastructure failures`.
  No push.

## Accepted architecture / invariants
* A2 remains unchanged: parallel notify units; compatible root device status gate
  after early ACTIVE SSH/crash IR, before startup apply; 60 s deadline, nonfatal
  failure with independent protection, real final DC obligation on success.
* Blocked enabled DC has Failed / ExecutionInfrastructureFailure /
  ownApplyAttempted=false and the gate diagnostic. Existing violation severity
  still activates; PolicyIncidentReporter and escalation are unchanged.
* No changes to wait helper, units, IPC, PreLogin, lifecycle, ownership or rollback.

## Completed / changed areas
* `fic/src/main.cpp`: production startup callback explicitly sets origin and
  ownApplyAttempted; message and status unchanged.
* `PolicyExecutionPlannerTests.cpp`: forwarding preserves classification/message,
  no backend call, independent work, Required/Disabled guards and incident activation.
* `IncidentApplyRoutingChecks.py`: checks actual production callback body and wiring
  to planner, complementing dynamic tests instead of trusting a duplicate lambda.
* `docs/startup-readiness.md`: documents the explicit classification.

## Validation
* Production callback static check PASS. Temporary-copy mutation checks reject
  missing/wrong origin, attempted=true, wrong status and an added backend call;
  unchanged production source PASS. No mutations applied to repository source.
* Clean local configure and build PASS:
  `cmake -S . -B build-startup-classification -DFIC_TARGET_PLATFORM=ubuntu-26.04`
  (real extracted development headers/system libpam; flags in CMakeCache).
  `cmake --build build-startup-classification --target fic policy_execution_planner_tests device_startup_readiness_tests policy_incident_reporter_tests -j4`.
* Targeted CTest: 3 PASS / 1 SKIP / 0 FAIL. Planner, reporter and production routing
  static checks PASS; device wait test SKIP (UID1000/root fixtures unavailable).
* New production regression also rejects the original base callback, not just
  synthetic mutations. Python syntax and `git diff --check` PASS.
* Logs: `/tmp/fic-startup-classification/{configure,build,ctest}.log`.

## Remaining / limits
* Docker is absent. Local clean Ubuntu26 build uses real PAM/udev headers extracted
  from downloaded development packages in `/tmp/fic-startup-classification/deps`
  and real system libpam; no stubs or host package installation.
* Device root-peer fixtures need UID 0 and an unmapped different UID. Current user
  is UID1000; sudo needs interactive authentication. No root fixture PASS claim.
* Full package native matrix intentionally not repeated; A2 sequencing/protocol
  did not change. Prior A2 results remain historical in startup validation docs.
* Known unrelated root full-CTest failures and runtime mutual-RPC/audit limitations
  from A2 remain outside scope. No broader cleanup is authorized by this follow-up.
