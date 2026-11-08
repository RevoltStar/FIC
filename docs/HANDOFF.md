# Current workspace

## Current base
* main; I5 base `e5696dca97971188e9248f3d1d174b5617f45b8e`.
* This changeset completes I5: `fix(pam): preserve ALT topology contracts across control changes`. One commit; no push.

## Current task
* Attachment 176f51c1: PAM I5 complete within the explicitly documented legacy ALT ownership boundary. Stop; do not start I6 automatically.

## Accepted architecture / invariants
* Production ALT profile/targets/aliases unchanged. Faillock: local-only auth+account and use_first_pass-local-only auth; strategies PreauthRequired/PreauthRequisite only. History: original tcb inside pwtxn begin→pwhistory→tcb→end. Existing storage, transaction/topology lock order, CAS/durability preserved.
* Physical blocks, selected graph, Structural proof and actual authentication are separate. History selected graph proof is local-user only; no domain history claim.
* Known-journal ALT release uses physical inspectForRelease; ordinary inspect/apply/control status require effectiveness. No orphan adoption. Other backend default delegates to previous inspect.
* ALT markers have no MutationId/generation receipt: coherent ABA recreation with an active journal record remains indistinguishable. Legacy release contract retained, NOT historical creator proof. No migration/schema/marker change.
* No I1–I4/C2/Required/parameter/lifecycle redesign. No control writer or automatic mode switching.

## Completed / changed areas
* RED→GREEN native: multi preserved blocks but could yield false enabled/history SUCCESS; added selected/full configured graph proofs with existing verifier.
* RED→GREEN native: provider disappearance/unsupported selection blocked release solely on effectiveness. Physical release now retains strict block/target/storage/lock checks independently.
* Two deterministic compensation RED→GREEN: faillock second-target failure and history postcondition failure previously erased concurrent admin edits. Unknown current bytes now preserved with CRITICAL; normal exact compensation remains successful. Old unexpected-publication test now requires refusal, not unsafe snapshot restore.
* Existing ALT manager tests extended for release, partial/mixed/drifted targets, malformed markers, storage and transaction contention. Existing native Driver/alt-control/run-i1 extended with I5 only; real policies/journal/RollbackExecutor/control facilities, no production scope narrowing.
* Authoritative mode matrix, ownership limits and evidence boundaries: docs/pam-r1-architecture-research.md §13; release clarification in docs/rollback.md. Compact evidence: tests/integration/pam-dependencies/i5-evidence.json; raw reports/logs ignored build-pam-i5. R1–I4 evidence untouched.

## Validation
* All5 Docker native gates: `FIC_PAM_GATE_STAGE=i5 bash tests/integration/pam-dependencies/run-i1.sh TAG PLATFORM BUILD_DIR` → fic +22 test targets built; 24/24 relevant CTest and production registry/Required audit PASS EACH. ALT additionally pam_fic_pwtxn built.
* Final before/after source receipts on all5: `6adc0f01bcfcde9a2e8e37f96edb6442ed6b1b4d4706fb8e11ed6a9be2fef77b`.
* `FIC_ALT_CONTROL_STEM=native-final bash tests/integration/pam-dependencies/alt-control.sh build-pam-r1-i3/alt-p11 --i5` + check-i5-control.py PASS. Native modes local→multi→ldap→krb5→krb5_ccreds→winbind→pkcs11→local; all targets/journal preserved by control. Explicit release PASS in every mode without changing selection.
* Unsupported alias/provider module absence/orphan/Prepared BEFORE+AFTER/RollbackFailed/AppliedAbsent and real readonly/rejected control actions PASS. Supplemental empty facilities returned disabled without target/journal mutation.
* Compensation targeted CTest 2/2 PASS after 2/2 RED. Harness bash -n, checker py_compile, evidence JSON assertions and git diff --check PASS.

## Remaining / limits
* No unfinished I5 implementation. Configuration proof only: minimal ALT lacks entry files login/sshd/sudo/su/sddm/gdm-password/lightdm/passwd and sss template. No packages added to hide gaps, no domain auth or I6/native history authentication. Default remember=0 does not prove positive history enforcement.
* No full project CTest or package E2E; host PAM untouched. Per-file atomic/CAS + compensation is not two-file atomicity; partial failure remains explicit, non-cooperating privileged writer race persists.
* ABA causal ownership limitation requires a separately agreed marker/receipt/version design if stronger guarantees are wanted; do not implement it automatically.
* Build caches: build-pam-i1/{debian12,debian13,ubuntu2404,ubuntu2604}, build-pam-r1-i3/alt-p11. Images fic-package-native:TAG and fic-pam-dependencies-native:alt-p11.
