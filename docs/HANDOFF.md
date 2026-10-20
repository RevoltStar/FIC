# Current working state

## Current base
* `main`; task base `36cbfd8c17c4c7f6eb8fe77d341243cabb14d616`, initially clean. Requested one documentation-only commit; no push.

## Current task
* SSH Verified Transaction Lifecycle architecture completed in `docs/ssh-verified-transaction-lifecycle-design.md`. No production/test/CMake/API/journal changes.

## Architecture / proposed decisions
* Recommend separate SSH coordinator using existing conditional writer/managed ownership and same verified engine; per-policy first, explicit batching later. This is a proposal, not implemented or approved production behavior.
* Full Success requires persistent/durability/ownership/runtime/cleanup/journal proofs. No automatic compensation after possible restart, runtime promotion, drift or residual mounts. In-memory exact-state compensation only under explicit guards; no historical whole-file restore after crash.
* Existing Prepared alone cannot encode runtime/action uncertainty. Proposed future typed SSH service operations/checkpoints inside existing MutationJournal, preserving outer statuses; atomic previous/target owner transitions and wrapper body fingerprints. Schema upgrade needs explicit approval; no migration code written.
* Separate external authority grants from FIC ownership and operation metadata baseline. No read-current→hash→authorize fallback.
* Release needs future ConfigurationOnly mode with remaining-enabled-policy proof, no proof of disabled value. ConfiguredInactive needs explicit public Deferred/availability contract before rollout. Existing Ubuntu/ALT LegacyReload stays distinct; no strict-to-legacy fallback.
* Durable intents represent may-have-happened at crash gaps, not invented exact syscall histories. Private mount boundaries/LSM/profile constraints remain; no automatic mount recovery.

## Confirmed current issues (not fixed)
* R1: post-install transaction failure + compensation CAS refusal → unconditional dropNewPrepared deletes provenance while installed FIC markers remain.
* R2: same-value Port refresh replaces old wrapper IDs with only new IDs; apply returns success, next rollback conflicts on old wrappers.
* R3: known wrapper ID with edited disabled-line body passes existing ID-only provenance and gets unwrapped.
* R4: apply and RollbackExecutor use different process mutexes; shared-lock comment is inaccurate. Cross-process serialization also absent.
* R5: unchanged owned scalar block can return apply=true after known NonCompliant weakening Match.
* Further static risks: Prepared recovery reload/commit before selected-value proof; current AtomicTargetState has no full metadata/mount witness; reload/active is not verified runtime.

## Validation
* Production call graphs, ownership/parser, conditional save/restore/durability, journal health/witness/finalization, adapter/generic boundaries, disable and incident projection audited against code.
* Docker Debian12 existing targeted CTest: 6/6 PASS, 4.63s (`mutation_journal_tests`, `rollback_executor_tests`, `ssh_runtime_tests`, `ssh_apply_rollback_tests`, `verified_config_service_tests`, `ssh_verified_activation_tests`).
* Four isolated probes using unchanged production objects + existing SshApplyTree/JournalOverride fake runner confirm R1/R2/R3/R5. No host SSH/runtime changes. Research harness/logs `/tmp/fic-ssh-lifecycle-audit/{repro.cpp,build.py,results.log,ctest.log}`; document includes reproduction plan/output. Initial missing runtime initialization was a harness issue, fixed with existing fixture setup.
* No new native OpenSSH/systemd/full-build gates: documentation-only work; previous native reports remain historical. Proposed lifecycle/recovery is not implemented/tested.
* `git diff --check` PASS; expected repository diff only this HANDOFF and the new design document.

## Remaining
* No implementation authorized by this task. Future first commits should fix R1/provenance and R5/compliance, then typed transitions/fingerprints/service checkpoints; full roadmap/test and 23-point crash matrices are in the design.
* Approval gates before relevant implementation: public Deferred/stopped contract, external grant administration, restart availability/budgets, journal schema/upgrade with missing historical wrapper evidence, private-boundary deployment and unsupported release closure handling.
