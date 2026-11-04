# Current workspace

## Current base
* Branch `main`; task base `58700459e8477968c76efd6384cd4e0073177054`.

## Current task
* Completed conversion of `sssd_i6_evidence_checks` to historical evidence verification (variant B). One commit; no push.

## Accepted architecture / invariants
* Accepted matrix commit: `96b88d2b40abff5cec9cd4352891401350e26719`; exact evidence.json SHA-256 `6dd6fac33b0846d97202dda46f13428bed17622a489ad006b21dddc8ff305306`, obtained with git show from that commit.
* Checker freezes its historical five platforms, 25 scenarios, 11 positive assertions and legacy build identities. It does not import current contracts or compare retained manifests with current sources.
* All existing compressed/raw report hash, matrix completeness, build/source binding, package, scenario, container, ownership/release and debugger assertions remain.
* PASS confirms only that historical matrix; it does not establish SSSD compatibility with current HEAD. New native runs/collection retain current-source/harness checks; source-manifest.py, collect-evidence.py, run-native.sh and contracts.py are unchanged. Historical evidence/reports are unchanged.

## Completed / changed areas
* `tests/integration/sssd-i6/check-evidence.py`: pinned accepted evidence bytes and historical expectations.
* `tests/integration/sssd-i6/test-historical-evidence.py`: seven isolated-copy regressions, including SSH/live-contract independence and evidence/report tampering/refusal.
* `tests/CMakeLists.txt`: existing CTest name retained, label historical-evidence replaces unit; separate regression test registered as unit/integration.
* SSSD runner README and `docs/sssd-verified-activation-design.md`: historical PASS boundary and separate current-source native contract documented.

## Validation
* Local checker PASS; unittest regression 7/7 PASS (1.202s).
* Existing Debian12 Docker builder: CMake configure PASS; CTest `^sssd_i6_(evidence_checks|historical_evidence_regression)$` 2/2 PASS (1.19s). JSON test discovery confirms historical-evidence/integration and absence of unit on the historical checker.
* Existing report-verification body preserved. Diff confirms no changes to production, native source/collection tools, current contracts, evidence.json or reports.
* `git diff --check` PASS.

## Remaining / limits
* No unfinished work for this task. No SSSD native matrix rerun and no production rebuild/full CTest: this change only affects Python evidence checking, test registration and documentation.
* Historical PASS must never be presented as current-HEAD native coverage. A newly accepted matrix requires explicit review and a new historical pin/frozen contract.
