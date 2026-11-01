# Current workspace

## Current base
* Branch main. Scope-coverage follow-up on parent `d1c4a0611ebffdc3107ec1b31289502313d1200c`; containing commit is the single follow-up commit. No push.

## Current task
* Attachment2a2fe01a: detect surviving ENABLE SSSD canonical domain scope drift before DisableRelease mutation.

## Accepted invariants / completed
* Existing requireOwnershipCoverage compares each remaining ENABLE policy's own unique valid completed Applied I4 owner with exact canonical assignments AND current canonical scopeIdentity(domainScope(input)). Policy-specific `scope mismatch` refuses before release transition/Prepared, file publication or runtime activation.
* Same helper repeats during acknowledgement and after final journal reproof immediately before typed acknowledgement. Existing post-publication surviving scope check remains, protecting against later drift.
* ReleaseOnly/uninstall remains exempt from administrative ENABLE ownership/scope requirements. No schema, receipt, I1–I5 engine, apply/REFRESH, CAS, recovery, dependency, platform, package lifecycle or generic activator changes; no adoption/repair/migration.
* Unit tests cover matching scope, assignment-preserving scope mismatch and either conflicting policy among multiple owners; previous missing/excess/value/legacy/unresolved/duplicate tests retained without weakening validRecord.
* New native remaining-enabled-scope-drift applies two real policies with implicit LDAP auth, explicitly sets identical auth_provider in foreign config and restarts SSSD as fixture setup. Production same-value apply independently confirms canonical scope drift. Subsequent disable reaches scope mismatch; raw journal, owned file bytes/inode, ENABLE config, foreign config and runtime generation remain unchanged.

## Changed areas
* fic/src/service/sssd/SssdTransactionCoordinator.{cpp,h} (header is test-only seam).
* tests/fic/service/SssdTransactionTests.cpp; existing tests/integration/sssd-i6 runner, guard, contracts and source-bound retained evidence.
* docs/sssd-verified-activation-design.md; runner README. Historical R1–I5 evidence untouched.

## Validation
* Full project build PASS in existing Debian12 Docker builder: build-sssd-i1/full/i6-scope-build.log.
* Targeted CTest3/3 PASS (rollback_executor_tests, sssd_transaction_tests, sssd_production_policy_tests),36.47s: i6-scope-targeted.log. Earlier unit-only run1/1 PASS.
* Five clean actual-package builds PASS. Native125/125 PASS:25 each Debian12/13, Ubuntu24.04/26.04, ALT p11. New scope gate5/5; positive multi-owner, active/offline release, REFRESH, ReleaseOnly/uninstall, ownership/ack, crash/retry and legacy regressions all PASS.
* Existing collect-evidence.py and check-evidence.py PASS with current source/harness/package bindings;260 compressed retained reports. Raw build receipts/results under build-sssd-i6/<platform>.
* Python compilation, shell syntax and git diff --check PASS. Host security state untouched; real package/policy actions only in isolated Docker/systemd fixtures.
* Full CTest PASS:217 PASS,0 FAIL,4 opt-in native SKIP /221,154.21s: i6-scope-full-ctest.log. Skipped separate opt-in gates: verified_config_service_native_tests, daemon_singleton_startup_native, maintenance_preflight_native, package_pam_hooks_native; the requested I6 native matrix ran separately in full.

## Remaining / boundaries
* Acceptance complete; no unresolved issue within this follow-up. Final scope/diff review and source-bound guard PASS; no push.
* Existing I6 supported topology/provider/private-boundary/metadata/legacy limitations remain. No production authentication, future LDAP availability or real-host boot proof. Preflight does not replace later transaction checks against concurrent drift.
