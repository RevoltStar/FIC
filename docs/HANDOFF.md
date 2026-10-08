# FIC handoff

## Current base

* Branch `main`; task base `dfa26c97272ae13b47de85571f130b5cf096b5c4`.

## Current task

* Implement production logind-backed session containment for Incident Response.

## Accepted architecture / invariants

* `IncidentController` owns severity/mode decisions; `LogindSessionContainmentBackend` only inventories, acts, and verifies. OFF/PASSIVE do not mutate sessions. Network quarantine remains the existing null backend.
* Session and user inventory have explicit `proven` status. Empty is success only after a successful logind reply and identity check; unproven inventory causes `DEGRADED`.
* Root, configured recovery-group members, greeter/service and unproven identities are never termination targets. Backend uses the existing secure recovery config reader and NSS group-membership implementation.
* `LockSession`/`LockedHint` do not prove desktop lock. Graphical STANDARD requests lock, then falls back to `TerminateSession` and checks logind disappearance.
* Logind actions are pinned to its unique D-Bus owner, with immediate identity recheck. The API does not offer an atomic check-and-terminate operation; the remaining narrow race was accepted by the user for explicit documentation.

## Completed

* Added typed inventory API; adapted `IncidentController` and existing fake backends.
* Added sd-bus logind transport, production backend, bounded checks, user-manager verification and production wiring.
* Added direct backend and controller-through-backend fake-logind tests; updated incident documentation.

## Changed areas

* `fic/src/session/`, `fic/src/incident/IncidentController.cpp`, `fic/src/incident/IncidentRecoveryConfigReader.*`, `fic/src/main.cpp`, `tests/fic/incident/`, `tests/CMakeLists.txt`, `fic/README.md`.

## Validation

* Base source evidence: production backend was `nullptr`; inventory API returned vectors; `toTerminate.empty()` could yield success after an empty failure result. This is source evidence, not an executable RED test.
* Debian 12 full build passed. CTest passed 141/141 tests with `mutation_journal_tests` excluded; that test binary passed separately under UID 1000. The first CTest run had one environment failure because Git rejected the bind-mounted `/src` as dubious ownership; rerun with container-local `safe.directory=/src` passed.
* Backend target built and test binary passed on Debian 13, Ubuntu 24.04 and ALT p11 PAM-ready images. Ubuntu 26.04 builder lacks PAM headers; backend and sd-bus transport passed isolated syntax compilation before the final controller-only change.
* `git diff --check` passed.

## Remaining

* No live host session mutation or real desktop/session E2E has been performed. Verify runtime D-Bus behavior in disposable systemd staging before deployment; fake transport tests do not prove real DE lock behavior.
