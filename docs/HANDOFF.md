# Current workspace

## Current base
* main; follow-up task base `3f61116f2ab12059702542428945fbfe9d5d344f`.
* Completion belongs to the commit containing this snapshot; no push.

## Current task
* Attachment a16c595f: SYSCTL crash-consistent ownership release completed and validated.

## Accepted architecture / invariants
* User-approved optional AtomicWriteOptions::beforePublish: exact fsynced temp snapshot → durable SYSCTL prepared receipt → rechecked CAS → rename. Refusal/exception/indeterminate journal prevents rename. Ordinary callers retain default behavior.
* Existing SysctlSettingState optional release intent: before snapshot, deterministic target bytes/metadata or absence, prepared inode receipt and temporary-legacy marker. Existing mutation ID binds operation; global schema3 unchanged, no migration/framework/background recovery.
* Explicit same-operation retry: exact before state resumes conditional release; exact prepared identity/metadata/bytes or planned absence gets durability barrier and journal completion without rewriting. Receipt is not rename proof; unknown state refuses without adoption/helper.
* Atomic terminal journal completion clears intent and updates surviving container identities. Generic RollbackFailed/discard and other SYSCTL apply cannot cross/erase unresolved release. Legacy origin/delegation and apply/REFRESH contracts preserved.
* Native helper unchanged: after durable completion only, error WARNING. Crash after terminal journal but before helper can skip auxiliary execution; no outbox/retry store.

## Completed / changed areas
* RED on task base: post-publication journal rename failure, reopen, retry fails stale inode. Tracked evidence includes exact test-only patch, exit1 and diagnostic; local raw log/source under build-sysctl-validation/release-crash-red*.
* Core AtomicFileWriter admission callback; SYSCTL deterministic plan/durability/retry; journal release serialization/validation/prepare/receipt/completion; RollbackExecutor retains pending typed state.
* Fault regressions cover intent/receipt/completion failures, indeterminate persistence, pre-rename CAS refusal, actual journal reopening, A/B/last absence/legacy delegation, identical bytes/new foreign inode, metadata drift, competing apply, idempotence and helper ordering.
* Debian12 package fixture enrolls two SYSCTL owners before prepare-uninstall/rollback all/remove/purge. Fresh source/harness/image/ELF-bound evidence replaces previous snapshot; no old PASS reused for changed code.
* Contract: docs/sysctl-lifecycle.md; related rollback/diagram/fixture documentation updated.

## Validation
* Final targeted5/5 PASS: sysctl_configuration_tests, sysctl_ownership_tests, atomic_file_writer_remove_tests, mutation_journal_tests, rollback_executor_tests. Log release-targeted.log.
* Full project build + actual Debian12 DEBs PASS. Full Debian12 CTest:219 passed,0 failed,4 opt-in skipped,223 registered;162.53s. Logs release-full-build-package.log and release-full-ctest.log.
* Fresh native SYSCTL and two unit suites each: Debian12(systemd252.39), Debian13(257.13), Ubuntu24.04(255.4), Ubuntu26.04(259.9), ALT p11(258.9) PASS. Actual helper/default-loader/exact-prefix behavior rerun against current code.
* Actual Debian12 daemon/CLI/two-owner package lifecycle PASS, including remove/purge, unchanged administrative configs, foreign sysctl source retained/applied by native helper. Installed daemon ELF matched rebuilt binary SHA.
* Source inventory recheck, Python/shell syntax, relevant static checks, historical I6 checker and git diff --check PASS. Current evidence: tests/integration/sysctl-ownership/evidence.json; local logs build-sysctl-validation/release-*.

## Remaining / limits
* No unfinished required follow-up work. No real reboot/power-loss experiment: deterministic syscall/persistence faults plus journal reopening. Runtime fixtures isolated; global kernel/sysfs readonly, only private-network leaves writable; no host security mutation.
* Existing stale inode from pre-intent code cannot be auto-resolved without historical proof. Unknown inode/bytes/metadata remains pending and fail-closed. Apply/REFRESH uncertainty is not expanded by this release-only recovery.
* Existing optimistic CAS residual race against noncooperating privileged writers remains. Crash after terminal journal can skip auxiliary helper as above.
* Package E2E is Debian12; other four have real backend/loader/unit gates. Supplemental ALT SDDM profile assertion was an unrelated known baseline from preceding task, outside this change.
* Four opt-in CTest skips: verified_config_service_native_tests, daemon_singleton_startup_native, maintenance_preflight_native, package_pam_hooks_native. Required SYSCTL/package native gates were run separately.
