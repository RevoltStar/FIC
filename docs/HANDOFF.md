# Current workspace

## Current base
* Branch main. Ownership-coverage follow-up completion snapshot on parent `219ab5b56c65b22dee7f52adabd1df0c1cd38262`; containing commit is the single follow-up commit. No push.

## Current task
* Attachment9a989db0: P1 remaining ENABLE SSSD ownership coverage fixed; implementation and requested acceptance complete. No next stage started.

## Accepted invariants / completed
* Administrative DisableRelease requires each remaining ENABLE policy's own unique valid completed Applied I4 owner and exact canonical section/key/normalized-value assignment set. Matching foreign effectiveness is insufficient. No missing/excess/conflicting/legacy/unresolved owner accepted.
* AdministrativeProof retains per-policy required assignments. One internal requireOwnershipCoverage helper runs before release transition creation/physical mutation, during acknowledgement and again after final journal reproof immediately before terminal proof.
* Releasing policy is excluded after release. Existing physical/provenance/semantic/runtime/A/B/C/P checks remain independent and mandatory. ReleaseOnly/uninstall deliberately does not acquire this administrative preservation rule.
* No I1–I5 engine, apply/REFRESH, recovery, schema3, payloadv3/receipt, dependency, platform or package lifecycle changes. No adoption, automatic sibling Apply/DISABLE or new recovery.
* Production changes limited to SssdTransactionCoordinator.cpp; header adds only a pure-helper declaration under existing FIC_ACTIVATOR_TESTING. Tests extend existing unit seam/native runner, no new infrastructure or production bypass.

## Changed areas
* Coordinator administrative coverage and policy-specific refusal diagnostics.
* SssdTransactionTests: full ownership plus missing/excess/partial/wrong-value/wrong-policy/legacy/unresolved/duplicate negative cases.
* Existing sssd-i6 runner: matching-foreign early refusal, acknowledgement-time missing ownership, changed unowned-mismatch early refusal; snapshots prove unchanged file/journal/config/SSSD generation. Matching gate separately proves ReleaseOnly with an unowned ENABLE sibling remains successful.
* Refreshed existing source-bound evidence/index:250 compressed reports,24 scenarios per platform. Historical R1–I5 reports/indexes unchanged. Contract in docs/sssd-verified-activation-design.md; fixture details in tests/integration/sssd-i6/README.md.

## Validation
* Full affected-consumer build PASS in fic-sssd-i1:full: build-sssd-i1/full/i6-coverage-full-build.log.
* Focused final3/3 CTest PASS (rollback_executor_tests, sssd_transaction_tests, sssd_production_policy_tests),14.19s: i6-coverage-unit-final.log.
* Full CTest PASS:217 PASS,0 FAIL,4 opt-in native SKIP /221,114.05s, including I6 source-bound guard and all available I1–I5/journal/SSH/PAM/SUDO/registry/GUI/package regressions. Log build-sssd-i1/full/i6-coverage-final-ctest.log.
* Skipped separate opt-in gates: verified_config_service_native_tests, daemon_singleton_startup_native, maintenance_preflight_native, package_pam_hooks_native. Explicit I6 Docker native gates were run independently.
* Five clean real-package native builds PASS,960 identical source inputs/3 packages each. Native120/120 PASS:24 each Debian12/13, Ubuntu24.04/26.04, ALT p11; both new gates PASS all5, plus existing positives, active/offline/multi-owner release, Refresh, faults/crash/retry, legacy upgrade and uninstall.
* Raw reports/build receipts: build-sssd-i6/<platform>/{native,build-receipt.json}; retained evidence under tests/integration/sssd-i6. Existing collector and check-evidence.py PASS with current source/harness/package bindings.
* Python compile, shell syntax, git diff --check PASS. Host security state untouched; real policy/package actions only in isolated systemd Docker fixtures.

## Remaining / boundaries
* No unresolved issue within this ownership-coverage follow-up. Existing I6 supported topology/provider/private-boundary/metadata/legacy limitations are unchanged; no claim of production authentication, future LDAP availability or real-host boot testing.
* Diagnostic Debian12 runs preceded final matrix and are not substituted for source-bound acceptance. Four optional native CTest skips above are explicit.
