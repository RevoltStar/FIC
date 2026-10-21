# Current working state

## Current base
* `main`; Stage 2 base `4578127d2798b7f1f3ee4fce543cded9b4a01af5`, initially clean. One completion commit requested: `fix(ssh): enforce compliance on unchanged owned state`; no push.

## Current task
* Stage 2 SSH R5 completed; final native/full validation passed. One completion commit, no push.

## Accepted architecture / invariants
* Ownership/journal/marker checks and shared-config Prepared gate precede effective commands. One typed compliance result before planning: Compliant permits owned/foreign no-op; unchanged owned NonCompliant/Unknown fails with reason before prepare/write/reload. Correct owned text alone is insufficient.
* Private SshRuntime verification/audit helpers retain Unknown for unavailable/malformed evidence and NonCompliant for observed mismatch. Existing bool verification contract and post-write checks retained. No new parser/public API/enum.
* Stage 1 unchanged: fresh Prepared discard only proven NotInstalled/no effects; installed/unknown writes retain Prepared. Full shared-config Prepared admission gate, no finishPrepared/blind reload/commit/discard. REFRESH requiring existing identity re-prepare refuses before write. Applied ID/full payload retained.
* Effective configuration from sshd -T is not verified live runtime. No generic/adapter/transaction/AtomicFileWriter/MutationJournal/schema/rollback/incident/platform changes.

## Completed / changed areas
* Production: `fic/src/modules/net/ssh/{Ssh.cpp,SshRuntime.cpp,SshRuntime.h}` only.
* Nine new R5 cases in existing full SSH executable: root/pubkey/maxtries Match, incompatible effective UsePAM, included Port, unavailable -T, missing parameter, invalid Port output, unavailable recursive Include audit. Each proves negative premise, two failed retries without effects, durable Applied preservation and recovery to successful owned no-op after external repair. Existing foreign compliant/malformed/orphan/Stage 1 cases retained.
* Total executable: 52 scenarios, 17 nested Stage 1 fault outcomes. No-write SUCCESS audit and boundaries documented in design §23.
* Existing native runner includes real OpenSSH semantic probes on Debian12/13 only; remaining distro gates retain full fixture executable. Temporary configs/keys only, no host/service restart. Conditional Match User root changes root/pubkey/maxtries; UsePAM disallowed in conditional Match; Include adds Port. Match all is already reflected by ordinary -T on tested OpenSSH; fixture runner is not a second OpenSSH implementation. UsePAM negative fixture injects incompatible effective output, not a claimed first-wins bypass via Include.

## Validation
* RED before production fix: six R5 cases fail by false apply=true after independently established NonCompliant/Unknown; `/tmp/fic-ssh-stage2-red.log`.
* Targeted SSH apply/rollback + runtime CTest PASS; `/tmp/fic-ssh-stage2-green.log`.
* Final native Docker Debian12/13, Ubuntu24.04/26.04, ALT p11: each 52 PASS/0 FAIL/0 SKIP plus 17 fault outcomes. Logs `build-ssh-provenance/<row>/native.log`; Debian additionally 3 OPENSSH PASS each (OpenSSH9.2/10.0p2).
* Full Debian12 configure/build + full CTest PASS: 188 PASS/0 FAIL/1 expected opt-in SKIP (`verified_config_service_native_tests`), 189 total, 181.94s. Includes SSH runtime/apply-rollback, MutationJournal/RollbackExecutor. `/tmp/fic-ssh-stage2-full-debian12.log`.
* Shell syntax checks and `git diff --check` PASS. Final scope/diff reviewed; production fic symbol scan confirms no test-only save-outcome setter.

## Remaining / limitations
* No unfinished Stage 2 implementation/validation. No push.
* R2 full previous/target REFRESH, R3 wrapper body fingerprints, R4 shared resource lock and coordinator/verified activation integration remain future work. Stage 3 must cover bypass of shared Prepared gate through rollback of another SSH policy; no RollbackExecutor redesign here.
* Schema 2 unresolved Prepared still requires explicit administrative resolution. Legacy value-change release→fresh apply and explicit rollback routes unchanged. Five userspaces on one WSL2 kernel, no real SSH activation/PAM/login or five-kernel VM claim.
