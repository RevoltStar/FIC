# Current working state

## Current base
* `main`, `2039ea5`; no push. M1 unfinished; SSH Stage3A deferred.

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
* Session repeats masks/quiescence before fresh journal load, then ALT pwhistory→faillock (ALT only), DM→DE→provider→password under one guard. Crash replays existing idempotent domain engines; leaves PasswordReleased/fence active. No hook detach/full finalization yet.
* ALT advisory inspectReadOnly reuses manager inspection without PID-lock/debug writes; original status/apply retain local locks. Standalone ALT topology mutators now require daemon admission; status keeps original resource serialization. Trust-sync still only hash-store serialized: lifecycle coordination unfinished.
* ALT detached PAM proof fixed: physical package target does not require Debian selection DB; trusted single-hop same-directory service aliases, explicitly declared Unix→TCB module alias. Escaping/unsafe/unknown aliases refuse. Attach semantics unchanged.

## Validation
* After restart: full Debian12 build + CTest 202 PASS / 1 expected native SKIP (203 total), 168.52s; `build-m1-evidence/alt-session-full-debian12.log`. Includes real ELF busy refusal for new ALT mutators, physical manager tests and DEB/ALT resource orchestration crash/failure tests.
* Native ALT p11 physical topology tests 2 PASS (targeted temporary CMake harness from exact production test sources), `build-m1-evidence/alt-readonly-native-build.log`. Initial harness errors (missing git/SQLite, then missing metadata source) fixed; final result GREEN.
* Native ALT stock detached proof + actual unsafe/ref/gate/alias negatives PASS: `build-m1-evidence/alt-detach-green.log`, `alt-detach-negative-native.log`. Root private container only, original PAM bytes/modes restored.
* Previous full Debian12 202 PASS / 1 SKIP at `build-m1-evidence/full-debian12.log`. Earlier native inventory/PM/masks matrix witnessed PASS, but old `/tmp/fic-m1-*` logs lost after reboot; research evidence remains committed.
* `git diff --check` PASS. Docker works. `fic-m1-masks-alt-p11` running, dummy units only; other four fixture containers stopped after reboot. Source mounted RO; no host security mutation.

## Remaining
* Next: closed fixed PAM hook detach + final domain proofs under same guard, then production operation preparation/recovery/install/abort controller, startup/mutator fence gates.
* Runtime ELF split/CMake/DEB/RPM prerequisites/version/lifetime/retention scripts and production finalizer/hook/path/boot/timer delivery NOT implemented. Existing package scripts still unsafe between commands and ignore stop errors.
* Must audit/move all security mutations from ALL package scripts under coordinator, preserving platform order. Trust-sync coordination remains.
* Actual FIC package install/upgrade/downgrade/remove/purge/reinstall/abort/autoremove/partial/crash/reboot matrix NOT done. Research/fixtures/parser/resource tests are not actual lifecycle safety proof.
* New *.py files in maintenance-lifecycle globally ignored; add explicitly. Build logs ignored intentionally. No M1 completion claim.
