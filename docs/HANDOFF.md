# Current workspace

## Current base / task
* Branch `main`; A2 base `62aa6022a2147dfc6080565584eb388e56a76d47`.
* A2 main/device startup orchestration complete. One requested commit:
  `fix(startup): coordinate main and device daemon readiness`; no push.

## Accepted architecture / invariants
* Main Wants=device; device Requires=main; neither orders startup After the other.
  Both retain notify/main/600s and their original READY points.
* Main's root/version/schema/API-checked served-status gate is after early ACTIVE
  SSH preblock/crash IR and before all initial policy execution. Monotonic 60 s,
  each IPC attempt <=1 s, pause <=100 ms. Existing IPC Client/peer validation.
* Nonfatal timeout: independent apply/FIREWALL still run; existing planner callback
  refuses enabled device-dependent DC writes and reports failure. Final DC obligation
  explicitly fails without claiming a reconcile. Successful gate retains real final
  reconcile. Historical startup flags never heal during later recovery.
* SIGTERM exits wait without startup apply/sockets/READY. UNINSTALLING skips gate.
  No lifecycle protocol, inventory barrier, new thread or ownership changes.

## Completed / changed areas
* `DeviceStartupReadiness`, main startup/pass integration, PolicyApplication's
  existing OwnExecutor forwarding and production unit graph.
* Real IPC fixtures, planner Required/disabled/independent tests, native A2 driver,
  related static checks. RPM fixture now discovers exact package names and obeys
  current Required password-quality activation before passwdqc.
* Authoritative contracts/results: `docs/startup-readiness.md`,
  `docs/startup-readiness-validation.md`, A2 package validation appendix.
  Compact native results/raw SHA-256: package-lifecycle evidence/startup-readiness-a2.json.

## Validation
* Full actual-PAM/Qt Debian12 project build PASS. Debian13/Ubuntu24/Ubuntu26 full
  fic compile/link PASS with respective profiles (Debian12 tooling, not native OS).
  Actual ALT p11 fic/device/CLI/infra/PAM build and wait-unit test PASS.
* Native Debian12 systemd: cold pair/main-only/device-only, 45 s delay + enabled DC,
  all-block-disabled final reconcile, incompatible/missing/DB/activation failures,
  permanent incident ACK, device restart, explicit main restart/stop, late recovery,
  PreLogin parser/auto-handoff and UNINSTALLING PASS.
* ACTIVE actual ISOLATE: SSH stopped + nft quarantine present before device wait;
  SIGTERM stop 0.114 s without startup apply. Not full PAM/session authentication.
* Actual DEB Debian12 and RPM ALT install/upgrade/reinstall/partial-release/retry/
  remove (+DEB purge)/emergency refusal and configuration retention gates PASS.
* Full CTest: 221 PASS / 4 SKIP / 5 FAIL of 230 initially. Related FIREWALL static
  test corrected; Git path test repeated with container safe.directory. Final affected
  CTest 7/7 PASS. Remaining unrelated root full-suite failures: incident-state RPM
  manifest assertion, identity hierarchy recommendation assertion, MutationJournal
  chmod fault under root. Separate current nonroot MutationJournal run PASS.
* Python/shell syntax and git diff --check PASS. Logs `/tmp/fic-a2/`; raw native
  evidence paths and initial harness-only failures are recorded in validation docs.

## Remaining / limits
* No unfinished A2 implementation. No new native runtime matrix on Debian13/
  Ubuntu24/Ubuntu26; no real VM boot, GUI rendering, physical devices or full ACTIVE
  authenticated login. Containers share Docker/WSL kernel.
* Existing approximately 30 s serial mutual-RPC runtime conflict and device-local
  audit's unsupported `incident` type remain outside scope; no DB schema changes.
* Prior I2 shared SSH publication contract remains unchanged; see its validation doc.
