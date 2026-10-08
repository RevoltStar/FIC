# FIC handoff

## Current base

* Branch `main`; task base `943b34b580b6a93e608b98d75f1bd8914a2e3353`.

## Current task

* Fix production containment identity and user-runtime class decisions.

## Accepted architecture / invariants

* `IncidentController` owns severity/mode decisions; `LogindSessionContainmentBackend` only inventories, acts, and verifies. OFF/PASSIVE do not mutate sessions. Network quarantine remains the existing null backend.
* Session and user inventory have explicit `proven` status. Empty is success only after a successful logind reply and identity check; unproven inventory causes `DEGRADED`.
* Root, configured recovery-group members, greeter/service and unproven identities are never termination targets. Backend uses the existing secure recovery config reader and NSS group-membership implementation.
* `LockSession`/`LockedHint` do not prove desktop lock. Graphical STANDARD requests lock, then falls back to `TerminateSession` and checks logind disappearance.
* Logind actions are pinned to its unique D-Bus owner, with immediate identity recheck. The API does not offer an atomic check-and-terminate operation; the remaining narrow race was accepted by the user for explicit documentation.
* Password-aging UID limits are not an account-type authority. Proven high-UID NSS/logind users with login shells can be ordinary; root/recovery, proven non-login service identities, and unknown identities remain distinct. Unknown degrades containment.
* Session-level termination only targets ordinary login classes. User-level ISOLATE permits manager/background classes within a proven ordinary user's runtime, but refuses root-oriented manager-early, greeter, lock-screen, unknown classes and identity mismatches.

## Completed

* Added typed inventory API; adapted `IncidentController` and existing fake backends.
* Added sd-bus logind transport, production backend, bounded checks, user-manager verification and production wiring.
* Added direct backend and controller-through-backend fake-logind tests; updated incident documentation.
* Corrected high-UID and user-runtime class classification, with raw identity-evidence injection through the production decision function and controller regressions.

## Changed areas

* This follow-up: `fic/src/session/LogindSessionContainmentBackend.{h,cpp}`, `tests/fic/incident/LogindSessionContainmentBackendTests.cpp`, `fic/README.md`.

## Validation

* RED on base behavior: manager runtime test failed in production `safeUser`; high-UID proof test failed at the password-aging UID ceiling.
* Debian 12 targeted backend/controller/access-gate/recovery-reader tests passed after the fix. Fresh full build and final incremental rebuild passed; final CTest passed 141/141 (excluding the separately tested journal).
* Backend target and direct test passed on Debian 13, Ubuntu 24.04 and ALT p11. Ubuntu 26.04 lacks PAM dev headers for a full configure; changed backend passed isolated syntax compilation.
* `mutation_journal_tests` from the fresh Debian 12 build passed separately under UID 1000.
* `git diff --check` passed.

## Remaining

* No live host session mutation or real desktop/session E2E has been performed. Verify runtime D-Bus behavior in disposable systemd staging before deployment; fake transport tests do not prove real DE lock behavior.
