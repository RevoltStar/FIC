# FIC handoff

## Current base

* branch: `main`
* base commit: `6c0021e`

## Current task

Incident Response architecture: fail-closed security state machine for the
authoritative incident severity. Partial implementation - see
`Not implemented / known limitations` below for the parts that are NOT done.

## Incident state model

Authoritative persistent state: `/opt/fic/lockstatus`, contents EXACTLY one of
`UNLOCKED\n`, `SOFT\n`, `STANDARD\n`, `HARD\n`, `ISOLATE\n`. No JSON, no reasons,
no timestamps, no history. History lives in the security audit trail.

Ordering: `UNLOCKED < SOFT < STANDARD < HARD < ISOLATE`.
`IncidentSeverity` (core) and `ViolationSeverity` (policy-declared, with a
separate `None` sentinel) live in
`fic-common/fic-core/include/fic/core/incident/IncidentSeverity.h`.
`ViolationSeverity::None` cannot be converted into an `IncidentSeverity`
(the conversion throws), so "NONE means unlocked" is structurally impossible.

`fic::incident::IncidentStateStore` (`fic/src/incident/`) owns the persistent
state and nothing else. Its `read()` is fail-closed: only a positively proven
severity token yields `Provenance::Proven`. Missing, symlink, non-regular,
wrong-metadata, malformed, unknown-token, oversize and changed-during-proof all
map to `Broken`/`Absent`, whose effective severity is ISOLATE.

## Durability model

`AtomicFileWriter`'s installed/durable distinction is honored explicitly:
`writeWithResult()` returns false for BOTH pre-install and post-rename
failures, so `IncidentStateStore` discriminates on `installed`, never on the
boolean. A rename that cannot be fsynced is NOT a security state - the effective
severity is forced to ISOLATE rather than trusting the published content.

`raiseToAtLeast()` = read -> target=max(current, requested) -> conditional
atomic write guarded by the proven state -> reread/recompute/retry on
precondition mismatch. Transitions are additionally serialized by a daemon-level
mutex, so two concurrent raises cannot interleave.

BROKEN_STATE fallback: when a severity cannot be made durable, FIC encodes the
incident as a DURABLY ABSENT object (which reads back as ISOLATE) using
`removeIfCurrentState()` + parent fsync + `ensureTargetAbsentDurableIfCurrentState()`.
This is never an unconditional unlink: a replacement between proof and unlink is
detected and NOT deleted. `clear()` has no unlink fallback at all - it fails
closed and the previous incident stays active.

## Policy failure semantics

`PolicyApplyResult` gained `failureOrigin` (`None`, `OwnApplyFailure`,
`RequiredDependencyBlocked`, `DependencyCycle`,
`ExecutionInfrastructureFailure`) and `ownApplyAttempted`. Origin is DIAGNOSTIC
ONLY and never suppresses an incident: `activatesIncident()` is exactly
`status == Failed`.

The rule: enabled policy + Failed -> raise THAT policy's own
`violation_severity`. There is no severity inheritance. A policy blocked by a
Required dependency is ITSELF Failed and therefore raises its own severity, so
`A(Required->B)` + failing B yields max(X, Y).

`fic::incident::PolicyIncidentReporter` is the only place policy failures
become incident state. Policy classes never call the controller. The daemon
calls the reporter from `run_daemon_apply_all_pass()` after the summary
completes; the merge is a max, so result iteration order cannot matter.

## Containment

`fic::incident::IncidentController` is the single runtime owner of common
incident state (`raise` / `clear` / `status` / `reconcile`). Runtime containment
state is separate from severity: `Inactive|Applying|Active|Degraded|Clearing`.
A containment failure never lowers the persisted severity.

Per severity:
* SOFT - nothing to contain yet.
* STANDARD - deny new ordinary logins, LOCK graphical sessions and VERIFY the
  lock; an unverifiable lock escalates to termination; SSH/TTY terminated.
* HARD - deny new logins, terminate all ordinary login sessions.
* ISOLATE - network quarantine first, then sessions AND the affected ordinary
  user runtime (including lingering user managers).

Recovery identities and service accounts are never terminated. `clear()` removes
the reversible containment state but NEVER unlocks a desktop session.

`SessionContainmentBackend` is the abstraction; the logind-backed production
implementation is NOT wired yet (see limitations).

## Packaging lifecycle

`fic --maintenance incident-init` is the ONLY sanctioned creator of the initial
state, and belongs to the main `fic` package. It creates only a genuinely absent
state, exclusively, proves the durability barrier, and re-reads through the
fail-closed parser before reporting success.

All auxiliary package hooks that did `if [ ! -f lockstatus ]; then printf '0'`
were REMOVED (Debian + ALT RPM). Under the new invariant a missing state is
ISOLATE, and no auxiliary package may synthesize UNLOCKED from it.
`incident_state_lifecycle_static_checks` locks this in (verified RED when the
insecure hook is reintroduced).

## PAM / recovery model

NOT IMPLEMENTED yet: `pam_fic_access.so`, `IncidentAccessGate` PAM capability,
daemon access states (`INITIALIZING/APPLYING/READY/STOPPING`),
`lock_exempt_fic_members`, `ssh_use_pam`, recovery-identity rules.
The persistent-state model they will read is already fail-closed and final.

## Completed

* Secure fail-closed incident state store + severity model.
* `violation_severity` config support (`ModuleConfigFileHandler`), policy
  metadata (`getViolationSeverity`/`getDefaultViolationSeverity`) and JSON/CLI
  exposure.
* `FailureOrigin` semantics wired into `PolicyExecutionPlanner`.
* `IncidentController` + `PolicyIncidentReporter` + daemon integration.
* IPC `incident_status` / `incident_raise` / `incident_clear`; CLI
  `incident status|raise|clear`. Legacy `lock`/`unlock`/`lockstatus` removed
  (they used the permissive 0/1 protocol).
* Startup crash reconciliation.
* Packaging lifecycle hardening (Debian + RPM) + regression test.

## Changed areas

* `fic-common/fic-core`: `fs/SecureStateFile.*`, `incident/IncidentSeverity.*`,
  `config/ModuleConfigFileHandler.*`.
* `fic-common/fic-policy`: `Policy.h`, `PolicyApplyResult.*`.
* `fic/src`: `incident/*`, `session/SessionContainmentBackend.h`,
  `policy/execution/PolicyExecutionPlanner.cpp`,
  `policy/registry/PolicyRegistryJson.cpp`, `daemon/main_function.*`, `main.cpp`.
* `fic-cli/src/main.cpp`, `packaging/deb/`, `packaging/rpm/`,
  `tests/fic/incident/`, `tests/integration/packaging/`.

## Validation

* `cmake --build build-check --target fic fic-cli` - clean.
* `ctest --test-dir build-check -j4` - 123/123 passed
  (includes `incident_state_store_tests` 16 scenarios,
  `incident_controller_tests` 11 scenarios, extended
  `policy_execution_planner_tests` incl. the full 5x5 required-dependency
  severity matrix, `incident_state_lifecycle_static_checks`).
* `git diff --check` - clean.

## Not implemented / known limitations

These parts of the task are NOT done. Nothing fakes them:

* `pam_fic_access.so` PAM module and the `IncidentAccessGate` capability; the
  login gate is therefore not enforced yet.
* Daemon access states and the `/run/fic/boot-ready` replacement.
* Recovery identity model (local-root proof, `fic` group exemption,
  `lock_exempt_fic_members`, PlatformProfile recovery service declarations).
* `ssh_use_pam` policy and its effective runtime proof.
* Logind-backed `SessionContainmentBackend` production implementation: the
  controller currently runs with no session backend, so session containment is
  NOT performed in production yet (only the decision logic is tested).
* FIC-owned nftables incident overlay (`table inet fic_incident`),
  `isolate_network_mode` / management networks, and the early boot guard unit.
* `fic-init-greeter` and the display gate.
* Device Control integration (`permanent_device_missing_severity` and the event
  to the main daemon) - `fic-dick` still performs its own legacy reaction.
* GUI surface for incident state.

Because the session backend and network backend are not wired, raising an
incident in the running daemon currently persists the severity and reports
runtime `Degraded` rather than claiming proven containment. That is the
fail-closed direction, but it is not the finished containment.
