# Current working state

## Current base
* `main`, `b6560e286699cde8e5ab7cc785d05a671eb064ec`. No push. M1 unfinished.
* Safe stage commits: M1-A `6a18e95f2c5220a49408d7ec538c5fe7ac09f8a3` (read-only preflight), M1-B current HEAD (exclusive standalone admission). Original base `90f8207`.

## Current task
* Complete M1, original attachment `9aef83ea-6744-4c0f-b167-aa1f49d956c5/Вставленный текст.txt`. SSH Stage3A deferred.
* User accepted finalizer delivery research; requested precise recurring retry/recovery contract/native tests first, then M1. Contract now in `docs/maintenance-finalizer-retry-lifecycle.md`; transport research is NOT actual FIC finalizer safety.
* Runtime package architecture ACCEPTED: preliminary runtime, one same engine, no cycles, strict version/ABI checks, native ordering, legacy support. Candidate scheme in docs/maintenance-runtime-package-design.md. NEW lifetime decision pending: native DEB joint purge removes runtime before main postrm purge; own runtime postrm/postun also lack helper. Proposed pre-removal retention requires finalized main removal in an earlier completed transaction; joint purge/autoremove can explicitly fail and require retry. Asked user to accept two stages vs require alternate lifetime. Do not implement incompatible user-visible erase behavior until answer.
* Native prerequisite/order/retention prototypes completed: all 4 DEB + ALT RPM fresh/upgrade/downgrade/mismatch, abort/failed erase; DEB failed-configure/configure-a. Logs evidence/runtime-{order,retention}-*.log. They are dummy packages, not FIC lifetime safety. Temporary ALT setup/container removed.

## Accepted architecture
* Same trusted daemon.lock for exclusive admission before operational journal, entire lifetime. Fixed typed C++ package-session DM→DE→PAM/hooks/proof, no arbitrary executor/environment FD authority/bypass.
* Durable typed fence outside package-deleted paths; purge/crash/reboot retains tombstone. Unknown/corrupt fail closed; no automatic ownership adoption. Closed install/reinstall/upgrade/abort/partial recovery needs fresh journal/PAM/incident/package proofs.
* Legacy: stop/prove managed units/cgroups/process identities; persistent masks prevent automatic activation through crash/reboot, restore only own masks. Manual/unidentifiable writer refuses. Independent old binary launch administratively excluded, not kernel-fenced.
* Deferred finalizer/InstalledButFenced: postinst never proves installed or clears fence. Final package version/coherence/manifest/journal/PAM/incident proofs under guard; package-manager locks retained through final proofs, not merely sampled FREE. Durable finish → unlock → normal start.
* Hybrid closed oneshot + hooks/path + boot + recurring timer, no permanent watcher. Temporary faults retry without total cap; rate/cost bounded, structural Blocked needs explicit closed recovery. Design defaults 60s cooldown/timer, 30s overall, 5s command, 1MiB captured output (enforcement not yet integrated).

## Completed / changed areas
* M1-A/B committed: four preflight routes use existing validatePersistentStateReadOnly; writer command classification + early common admission. Native holder rejects releases and config/incident/bootstrap mutators without changes. Existing resource-serialized ALT topology/trust-sync retained; not whole-package exclusion. Docs `maintenance-admission.md`.
* Uncommitted `PackageLifecycleState.*`: private typed CAS/durable store, bounded SecureStateFile 4096-byte read, duplicate/unknown JSON rejection, operation/phase validation, new-operation/recovery transitions, InstalledButFenced, durable retry boot/BOOTTIME admission and typed failure classification. Requires PID-bound guard. NOT integrated into startup/lifecycle; store API does not substitute proof-controller.
* Uncommitted StoppedWritersProof parser accepts terminal loaded/masked/not-found + zero PIDs/no Job; not actual cgroup/manual process proof.
* Research fixtures/evidence `tests/integration/maintenance-finalizer-research/`: accepted dpkg/RPM/path research, new recurring retry tests and operation-owned empty-file mask prerequisite tests.

## Validation
* Full Debian12 configure/build + CTest: 196 PASS, 1 expected generic native SKIP (197 total), 177.60s; `/tmp/fic-m1-full-debian12-retry.log`. Latest targeted fic/test build + 11 CTests PASS: `/tmp/fic-m1-admission-foundation-green.log` (includes later store/crash/parser changes). Original full run failed comment path literal; fixed. A separate run lacking git safe.directory failed infrastructure check; corrected GREEN.
* Native standalone g++ store/retry/crash suites PASS five userspaces (`/tmp/fic-m1-state-retry-crash-{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}.log`): 128 temporary retries, cooldown/restart, stale CAS, clock rollback/new boot ID, structural block; SIGKILL at 12 durable phases in initial matrix (latest model adds separately verified RemovedTombstone phase), exact restart state and contention. Injected boot IDs are not real kernel reboot.
* Native systemd retry protocol PASS all five: >=8 temporary attempts without completion event; hook storm cadence; structural block across timer intervals; crash/timeout recovery; manager reexec; tombstone retained after fixture unit removal. Scaled 250/300/700ms only fixture values. Logs evidence/retry-lifecycle-*.log.
* Native unique operation-owned empty file masks PASS five userspaces: enabled dummy legacy unit cannot start after manager reexec/private container PID1 restart. Logs evidence/private-mask-*.log. Not actual FIC masks/purge/recovery.
* Accepted research matrix: D12 systemd252/dpkg1.21; D13 257/1.22; U24 255/1.22; U26 259/1.23; ALT258/RPM4.13. Five userspaces share WSL2 kernel. No host security/package mutation. Temporary systemd retry containers removed.
* Latest phase model distinguishes ReleaseComplete (security release only, still pending actual removal proof) from RemovedTombstone. fic + 9 targeted CTests PASS after this change: /tmp/fic-m1-removal-tombstone-foundation.log; actual SIGKILL test now covers 13 phases.
* `git diff --check` PASS. New research *.py/*.log globally ignored; add explicitly if committing. No research/store commit yet.

## Remaining
* Resolve runtime retention/two-transaction removal decision (pre-payload runtime delivery itself is accepted). Then actual package-session, lifecycle path/provenance masks, process/cgroup/manual proof, startup/mutator fence gating, proof-controller, all closed recovery flows and production finalizer/hook/path/boot/timer delivery.
* Generated DEB/RPM scripts still have original critical operations outside package-wide admission; RPM failed-stop/no-systemd defects and package gaps remain. No M1 completion claim.
* Actual FIC install/erase/upgrade/abort/reinstall, package manifest/lock-retention proofs, failed-stop/partial release/crash/reboot matrix, production budget enforcement and final broad/native package validation remain. Real kernel reboot/power loss and hostile privileged writers not tested.
