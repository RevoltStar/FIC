# Current working state

## Current base
* `main`, base `1782cc636364b8bb5c0ec0c1463250282c773cfe`, initially clean. One follow-up commit requested; no push.

## Current task
* Hardening standalone VerifiedConfigServiceActivator: loaded launch contract, propagation preflight, independent fixture mount-ID attestation. No policy/SSH/apply/rollback/MutationJournal or existing production activation paths touched.

## Accepted architecture / invariants
* User chose pre-established private parent boundaries. Component ONLY checks them; no automatic permanent boundaries, no global propagation or unit/launch-model changes. Real-host provisioning is future deployment work.
* Same mount namespace/root as PID1, active Type=notify/main, RO tmpfs, sticky observer, identity-safe reverse ordinary umount; public API/ActivationResult unchanged.
* Shared/shared-slave publication parents (including workspace) fail before mount. Private/non-shared slave accepted; incoming events fail activation. Check/attach race against CAP_SYS_ADMIN remains outside guarantee.
* Initial unsupported launch contract fails closed; changed captured values after preflight yield InterferenceDetected. Exec*Ex typed path/argv/flags excludes mutable runtime status; PID1 peer checked. Loaded properties + unit/drop-in fingerprints and manager environment compared repeatedly. EnvironmentFile/credentials/FD-store/alternative namespaces unsupported.
* Prior poll blind spots and accepted cleanup check/umount race remain explicit. No SIGKILL recovery/adoption; residuals refused.

## Completed / changed areas
* `fic/src/service/VerifiedConfigLaunchContract.*`, Systemd, MountSupport, activator preflight.
* New component test sources, CMake lists and component documentation.
* Native fixture direct statx on same read FDs, positive published-ID checks and negative identical original-FD reads.
* Real unit/daemon-reload/env/drop-in/READY races; peer namespaces with private/slave boundaries under shared ancestor; AtomicFileWriter before/after and sibling rename during activation.

## Validation
* Exact final source, native Docker Debian12/13, Ubuntu24.04, ALT p11: 50 PASS / 0 SKIP each; `/tmp/fic-hardening-{d12,d13,u24,alt}.log`. Individual per-file SHA + mount IDs checked against request/publication; negative original-FD attestation rejected.
* Full Debian12 configure/build PASS; full CTest 186 PASS / 1 expected native opt-in SKIP / 0 FAIL (187 tests; all 185 pre-existing tests pass), `/tmp/fic-hardening-full-d12.log`.
* Full build updated after final test-fixture SHA assertion; related CTest PASS, `/tmp/fic-hardening-final-targets.log`. No privileged host validation; Docker build drops DAC override/read-search.
* git diff --check / cached diff check and bash -n native runner PASS. Scope reviewed: only service component, its tests/CMake and documentation; public API untouched.

## Remaining / limits
* No unfinished implementation. One follow-up commit, no push.
* Private parent-boundary provisioning on real systems is future deployment work, deliberately not implemented here.
* All native userspaces share kernel 6.6.87.2-microsoft-standard-WSL2. No separate Linux VM/physical-host kernel validation. Native tests explicitly construct topology; default Docker mounts are not the only topology tested.
* Known poll blind spots, sequential launch checks, parent-check/attach and cleanup-check/umount races against CAP_SYS_ADMIN remain explicit. No claim of arbitrary privileged-adversary protection or atomic conditional restart.
