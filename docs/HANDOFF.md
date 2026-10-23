# Current working state

## Current base
* `main`; stage base `94d8904` (latest implementation commit: `git log -1`); no push. M1 unfinished; SSH Stage3A deferred.

## Current task
* Complete M1 (attachment `9aef83ea-6744-4c0f-b167-aa1f49d956c5`). Continue autonomously; no checkpoint-only stop.
* Accepted architecture: AGENTS.md §17, `maintenance-runtime-package-design.md`, `maintenance-finalizer-retry-lifecycle.md`. No pending design question.

## Accepted invariants
* One engine/daemon.lock; closed fixed package-session, no arbitrary executor/FD authority/bypass.
* Durable root-controlled fence/tombstone outside deleted trees, masks + unit/cgroup/process proof; manual legacy launches administratively forbidden, unknown writers refuse.
* Preliminary runtime owns same ELF; exact version/ABI/order, two-stage runtime erase requires previous completed transaction removal proof plus fresh proofs. Joint autoremove may refuse.
* Postinst leaves InstalledButFenced. Deferred finalizer holds actual PM locks + daemon admission through proofs; recurring bounded-cost retries without total cap; structural faults remain fenced. No watcher.
* Upgrade quiesces without policy/PAM release. Only Remove performs release chain.

## Completed / changed areas
* Committed M1-A/B and durable foundations in `2039ea5`. New work: immutable legacy writer inventory, typed native package DB snapshots under matching locks, shared fixed resource operations for four existing maintenance routes, resource-stage `PackageReleaseSession` (not yet wired to CLI).
* Resource-stage `PackageReleaseSession` committed in 94d8904. `completeRelease` adds fresh read-only domain final proofs, fixed PAM hook detach (other profiles before gate, loadability/effective gate proof before last removal), independent final journal/domain/hook proof and durable ReleaseComplete. Not wired to package CLI. No post-transaction finalization/removal proof.
* New `PackagePamHooks` uses native updater/ALT existing topology engine, no compensation/adoption. Provider/password backends expose ProveReleased reusing existing independent final proof, no new release engine. Unknown profile/unsafe files refuse before mutation; successful updater exit does not replace physical proof.
* New `PackageLifecycleAdmission` wired in main: daemon + exclusive standalone require durable Installed BEFORE config/SSH containment/journal; trust-sync checks early and again under its existing hash-store lock via internal callback. Canonical state path `/var/lib/fic-lifecycle/state.json`. MISSING state refuses; install/recovery controller NOT implemented, so intermediate build cannot normal-start without a legitimately finalized state. Do not add manual Installed/bypass.
* New snapshot-bound lifecycle confirmDurable prevents acknowledging visible terminal phase after directory-fsync failure. New argv-based refusal detects canonical shell script writers; kernel exe/fingerprint still authoritative, argv never authorizes unknown root process.
* ALT advisory inspectReadOnly reuses manager inspection without PID-lock/debug writes; original status/apply retain local locks. Standalone ALT topology mutators now require daemon admission; status keeps original resource serialization. Trust-sync reader recheck now implemented, but publication/final proof side must take same hash-store lock in future coordinator; not yet complete coordination.
* ALT detached PAM proof fixed: physical package target does not require Debian selection DB; trusted single-hop same-directory service aliases, explicitly declared Unix→TCB module alias. Escaping/unsafe/unknown aliases refuse. Attach semantics unchanged.

## Validation
* Hook/domain/session tests 4 PASS: `build-m1-evidence/complete-release-tests.log`; includes partial hook failures and SIGKILL, no post-detach resource writes.
* Actual native package PAM infrastructure (real updater/actual module loadability), 2 tests PASS each on D12/D13/U24/U26/ALT: `pam-hooks-native-{debian12,debian13,ubuntu2404,ubuntu2604}.log`, `pam-hooks-native-alt-p11-green.log` in build-m1-evidence. Fixtures, NOT actual FIC lifecycle/authentication. ALT added libpam0-devel only inside disposable fixture, restored network none. ALT initial unit failed /run noexec; fixture moved to private /var/lib.
* New daemon real ELF pending/missing/corrupt/tombstone admission + hash-store callback under real lock + snapshot-bound phase durability tests PASS: `trust-lifecycle-admission-tests.log`, `lifecycle-durability-tests.log`.
* Full D12 configure/build + CTest 204 PASS / 2 expected native SKIP (206 total), 162.31s: `build-m1-evidence/hooks-admission-full-debian12-green.log`. Original static failure was a comment literal, fixed. Then deterministic unknown-process fixture build + related CTests 3 PASS: `census-readiness-fixture-debian12.log`.
* Native script census with explicit independent ELF/readiness fixture PASS five userspaces: `build-m1-evidence/script-writer-census-*-fixed-fixture.log`. Old harness's renamed /bin/sleep failed on U26 uutils; fixed rather than accepting a flaky rerun. `build-native.sh` now also builds m1-unknown-writer; invoke m1-process-tests /usr/local/bin/m1-unknown-writer.
* After restart: full Debian12 build + CTest 202 PASS / 1 expected native SKIP (203 total), 168.52s; `build-m1-evidence/alt-session-full-debian12.log`. Includes real ELF busy refusal for new ALT mutators, physical manager tests and DEB/ALT resource orchestration crash/failure tests.
* Native ALT p11 physical topology tests 2 PASS (targeted temporary CMake harness from exact production test sources), `build-m1-evidence/alt-readonly-native-build.log`. Initial harness errors (missing git/SQLite, then missing metadata source) fixed; final result GREEN.
* Native ALT stock detached proof + actual unsafe/ref/gate/alias negatives PASS: `build-m1-evidence/alt-detach-green.log`, `alt-detach-negative-native.log`. Root private container only, original PAM bytes/modes restored.
* Previous full Debian12 202 PASS / 1 SKIP at `build-m1-evidence/full-debian12.log`. Earlier native inventory/PM/masks matrix witnessed PASS, but old `/tmp/fic-m1-*` logs lost after reboot; research evidence remains committed.
* `git diff --check` PASS. Docker works. All five `fic-m1-masks-*` running again, dummy units only. Source mounted RO; no host security mutation.

## Remaining
* Next: production operation preparation/recovery/install/abort controller, runtime split and actual finalizer. Hook/admission stage ready for a coherent intermediate commit; M1 not complete.
* IMPORTANT next design detail discovered: masks must persist across abort/reinstall/upgrade while operation IDs change. Existing PackageUnitMasks.prepare rejects prior operation-owned links as custom. Prefer explicit mask provenance ID distinct from operation ID in typed fence (development schema may change cleanly; no dual-read/migration), preserve original mask plan through recovery. Do not unlink masks to prepare a new operation. Writer inventories remain operation-bound. This is internal realization of accepted retained masks contract, not a reason to stop/reopen accepted architecture.
* Coordinator fence publication/final proof must hold existing hash-store lock (callback recheck only implements reader side). Main startup gate is already strict; do not claim installable lifecycle until production bootstrap/recovery exists.
* Runtime ELF split/CMake/DEB/RPM prerequisites/version/lifetime/retention scripts and production finalizer/hook/path/boot/timer delivery NOT implemented. Existing package scripts still unsafe between commands and ignore stop errors.
* Must audit/move all security mutations from ALL package scripts under coordinator, preserving platform order. Trust-sync coordination remains.
* Actual FIC package install/upgrade/downgrade/remove/purge/reinstall/abort/autoremove/partial/crash/reboot matrix NOT done. Research/fixtures/parser/resource tests are not actual lifecycle safety proof.
* New *.py files in maintenance-lifecycle globally ignored; add explicitly. Build logs ignored intentionally. No M1 completion claim.
