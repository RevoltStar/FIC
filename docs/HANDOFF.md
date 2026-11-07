# Current workspace

## Current base
* main; I2 base `04906dfd8683ddb3f2561a37282c329316aabb80`.
* This changeset completes I2: `fix(pam): reconcile ownership before topology mutations`. No push.

## Current task
* Attachment ec854788: PAM I2 complete. Stop after its single commit; do not start I4–I6 automatically.

## Accepted architecture / invariants
* Existing C2 executor is the single writer. Ordinary apply: fresh snapshot → existing exact selected Active Prepared history completion → both-domain ownership admission → Structural preflight using the SAME requested snapshot → existing drift gate → unchanged planner/transition → existing AFTER proofs.
* Explicit transition/rollback/release does not use ordinary admission or activation preflight. Exact historical recovery is independent of new intent; no additional Quality recovery.
* No adoption, schema/marker migration, parameter-backend, I3 Required, planner semantics or package lifecycle changes. ALT marker causal ambiguity remains; no new historical ownership guarantee.

## Completed / changed areas
* Reproduced peer mutation before rejection for dangling Q/H provenance, early preflight blocking exact recovery, and preflight drift. Four RED wiring groups on base production code; GREEN on final code.
* Production changes only PamPasswordTopologyCoordinator.cpp and PamPasswordTopologyTransitionExecutor.{h,cpp}; shared existing transition implementation, no parallel ownership grammar.
* Wiring regressions cover both peers and active statuses, byte-exact rejection, honest no-mutation result, explicit absent-ownership release, Normal/Initial exact recovery with changed new intent and rejected preflight, and preflight drift.
* Real faillock manager/Structural verifier regressions retain journal on neutral+foreign with active records. ALT history real manager/journal matrix covers idempotency, dangling/corrupt/partial/orphan ownership, unsupported duplicate tcb and preservation of supported foreign account rules (explicit verifier seam).
* Existing provider release independence, C2 compensation/drift, faillock exact-ID partial recovery and ALT storage/CAS tests retained. No production changes to these paths.
* Contract/table: docs/pam-r1-architecture-research.md §11 and docs/rollback.md PAM section. Historical R1/I1 evidence unchanged; harness supports FIC_PAM_GATE_STAGE=i2 to keep output separate.

## Validation
* All five Docker native toolchains (D12/D13/U24/U26/ALT p11): `FIC_PAM_GATE_STAGE=i2 bash tests/integration/pam-dependencies/run-i1.sh TAG PLATFORM BUILD_DIR` → fic +20 test targets built, 22/22 relevant CTest PASS on EACH; production registry audit PASS.
* Cached build dirs: build-pam-i1/{debian12,debian13,ubuntu2404,ubuntu2604}, build-pam-r1-i3/alt-p11. Final before/after source receipts all match `9737b219fbc71e106b0e33881262a0046720bd371d6eca1f33a9987afc476e47`; final binaries checked for new regression strings to rule out stale objects.
* Four disposable native-initial-probe.sh runs: actual pam_chauthtok, two changes succeed/reuse rejected, D12/D13/U24/U26. No host PAM changes.
* Raw logs in ignored build-pam-i2; compact hashes/results in tests/integration/pam-dependencies/i2-evidence.json. Earlier source-drift/stale-object and incorrect ALT-fixture expectation iterations are NOT final PASS.
* Harness bash -n, evidence aggregation assertions and git diff --check PASS.

## Remaining / limits
* No unfinished I2 implementation. Full project CTest, I6 functional authentication/FIC activation matrix, native ALT passwdqc/history consumer and package E2E were not run.
* ALT markers lack MutationId-based causal binding; do not broaden ownership or migrate them automatically. Unsupported/ambiguous states remain fail-closed. Quality Prepared package-release lifecycle remains unchanged.
