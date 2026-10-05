# FIC handoff

## Current base

* Branch: `main`; task base: `742474baed88632906c72b49b96b0f7d2a7521f1`.

## Current task

Focused security hardening of the existing Incident Response core. The PAM gate,
production logind and nftables backends, early guard, recovery identities,
greeter/display gate, Device Control integration and GUI are outside this task.

## Accepted architecture and invariants

* `/opt/fic/lockstatus` is the only persistent incident severity. Only exact
  `UNLOCKED\n`, `SOFT\n`, `STANDARD\n`, `HARD\n`, `ISOLATE\n` with proven metadata
  are trusted. Missing, malformed, raced or otherwise unprovable state means
  effective ISOLATE. Runtime raise cannot create a weaker file from absence.
* `IncidentStateStore` owns persistence. Post-rename durability failure triggers
  exact-state retry, then conditional durable absence fallback. Failed clear
  compensates a published UNLOCKED by restoring the previous severity durably
  or encoding BROKEN/ISOLATE. Failure never counts as successful unlock.
* `IncidentController` owns runtime containment. `ok` requires durable state
  and all applicable containment proofs. The absent PAM gate and production
  session/network backends are reported as unavailable, so production
  STANDARD/HARD/ISOLATE remains DEGRADED even when severity persists.
  Failed clear reconciles the resulting effective severity, including a new
  BROKEN/ISOLATE state, instead of reusing the old runtime proof.
* Policy failures feed `PolicyIncidentReporter` from startup/periodic and the
  three manual apply entrypoints. Required/Recommended dependency semantics
  and policy-owned violation severities are unchanged. No product defaults
  have been assigned where the product has not specified them.
* Main package `incident-init` runs only on initial Debian/RPM install. Upgrade
  and auxiliary packages do not create UNLOCKED from missing state. Generic
  package ownership/mode normalization excludes `lockstatus`.
* Production state metadata: file root:fic 0640, `/opt/fic` root:fic 2750,
  regular single-link object. Secure read checks same-size in-place changes.

## Completed

* Hardened state-store raise, durability fallback and clear compensation.
* Hardened controller proof, aggregation, notification deduplication and
  audit/notify wiring; manual apply now reports incidents.
* Hardened Debian and ALT RPM generated lifecycle scripts and committed
  dedicated packaging and apply-routing checks.
* Added incident state, controller, reporter and packaging regressions.

## Validation

* Fresh `/tmp/fic-incident-hardening-check` configure for Ubuntu 24.04 and
  full build passed.
* Fresh `ctest -N` registered 125 tests, including incident state/controller,
  policy reporter, apply routing, planner and packaging lifecycle checks.
* Fresh full CTest outside sandbox: 125/125 passed; one unrelated
  `command_hash_batch_tests` is marked Skipped by its own test gate.
* First sandbox CTest had `session_event_server_tests` fail on denied Unix
  socket `bind`; the same test and full suite passed outside sandbox.

## Remaining

* No native package install/upgrade smoke was run; lifecycle is checked from
  generated-script source. No host policy apply, PAM, logind or nftables
  runtime validation was run.
* Production PAM access gate, session backend and network quarantine are still
  absent. A persisted incident therefore does not imply active containment.
* Per-policy product default `violation_severity` decisions remain unspecified;
  the base `Policy` default is `None`.
