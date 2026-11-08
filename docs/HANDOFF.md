# Current workspace

## Current base
* main; follow-up base `ace474877aa360b8702446b3a730a678b73a4610`.
* This changeset: `fix(pam): allow ALT history ownership release with foreign provider`. One commit; no push.

## Current task
* Attachment 1a543519: I5 ALT PasswordHistory ownership-safe release follow-up. Do not start I6.

## Accepted architecture / invariants
* Ordinary inspect/enable still reject foreign pwhistory through includes. Physical release must not require absence of that independent provider.
* Strict local inspectTopology/inspectBlock, trusted target/storage, topology→transaction locks, CAS, durability and journal provenance retained. Direct foreign rules that violate managed-target grammar remain unsupported.
* Only AltTcbManaged PasswordHistory unrecorded rollback uses existing physical inspector: own-block absence is AlreadyReleased; present orphan remains Conflict, never adopted/deleted.
* API, markers/MutationJournal schema, C2, ALT faillock, activation policy, Required, pwtxn and package lifecycle unchanged. Legacy ALT causal ownership/ABA and non-cooperating writer race limits remain.

## Completed / changed areas
* Unit + native RED on unchanged base: foreign history include blocked exact release; Applied + absent block also conflicted solely on foreign provider.
* Manager gates verifyNoExternalHistory on ordinary inspection only and removes that condition from disable. PamRollback.cpp narrowly uses physical inspection for ALT History no-active-record classification, allowing idempotent repeated rollback.
* Unit fixture and existing native I5 Driver/checker cover strict ordinary refusal, real journal-backed release, exact foreign include/file + tcb preservation, AlreadyReleased without physical mutation, journal completion, repeated rollback unchanged, malformed block and orphan refusal.
* Native damaged-block fixture compares exact History/foreign suffix because the separate lockout rollback legitimately removes faillock bytes from the same file. Earlier broad whole-file assertion was a fixture error, not a production regression.
* docs/pam-r1-architecture-research.md §13 follow-up and separate i5-history-release-evidence.json record current results; historical i5-evidence.json and R1–I4 artifacts unchanged.

## Validation
* ALT p11 + Debian12: `FIC_PAM_GATE_STAGE=i5 bash tests/integration/pam-dependencies/run-i1.sh TAG PLATFORM BUILD_DIR`: fic +22 test targets built, 24/24 relevant CTest and production registry/Required audit PASS each; ALT also pam_fic_pwtxn built.
* `FIC_ALT_CONTROL_STEM=followup-green bash tests/integration/pam-dependencies/alt-control.sh build-pam-r1-i3/alt-p11 --i5`: configuration/control/journal-backed foreign-history regressions PASS. Raw RED/GREEN reports/logs in ignored build-pam-i5; compact evidence contains hashes/source receipts.
* checker py_compile, harness bash -n, evidence consistency and git diff --check PASS.

## Remaining / limits
* No I6, full project CTest, package E2E or actual PAM authentication. Debian13/Ubuntu24/Ubuntu26 not repeated for this ALT-only route change. Existing I5 five-profile results remain historical evidence for the previous commit.
* Minimal ALT image lacks login/sshd/sudo/su/sddm/gdm-password/lightdm/passwd entry files and sss template; no packages installed to hide those gaps. Default remember=0 is not positive enforcement proof.
* ALT markers lack MutationId/generation receipt: exact lookalike recreation under an active journal record cannot prove historical creator. No migration/adoption/new recovery added.
* Caches: build-pam-r1-i3/alt-p11, build-pam-i1/debian12; images fic-pam-dependencies-native:alt-p11 and fic-package-native:debian12. Host PAM untouched.
