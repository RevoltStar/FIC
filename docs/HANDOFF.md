# Current workspace

## Current base
* main; I4 base `f2c6941bd06b0547e8f4d64dfcabe3bcbd383d8a`.
* This changeset completes I4: `fix(pam): enforce parameter backend ownership contracts`. One commit; no push.

## Current task
* Attachment 967b88c1: PAM I4 complete. Stop; do not start I5/I6 automatically.

## Accepted architecture / invariants
* Suppression ownership remains ID-only. Strict FIC structure/identity/MutationId/suppression IDs and valid same-key raw semantics. Same-key comment/whitespace changes allowed; rollback restores CURRENT raw bytes exactly. Historical raw-byte immutability is not proven and is NOT an I4 defect. No fingerprints, journal fields, migration or new recovery.
* Existing ManagedEntry/Flag lifecycles, C2 single writer/I2 recovery/admission and I3 Required remain. C2 parameter Structural callback runs after exact recovery/admission and before planner; cached typed parameter must match SAME requested snapshot; AFTER proof repeats. Explicit release stays independent of activation proof.
* No MutationJournal/schema, C2 planner/recovery, ALT topology/markers, parameter route, I3 or package lifecycle changes.

## Completed / changed areas
* RED→GREEN: C2 parameter could mutate/return SUCCESS after provider module disappeared. Shared unchanged I1 joint Structural proof extracted into PamCapabilityVerifier, reused by activation and parameter; missing/bypass/peer trust now fails before mutation. Target comparison handles 007 == 7 and rejects stale/disabled intent.
* RED→GREEN: suppression wrapper under the expected globally unique MutationId with changed provider/policy could be ignored as foreign. Existing flag inspector and release primitive now reject that identity collision. Accepted same-key raw edits remain valid and byte-exact on release.
* Production: PamCapabilityVerifier.{h,cpp}; policies/PamCapabilityActivationPolicy.cpp; policies/PamPasswordHistoryOptionPolicy.cpp; PamProviderManagedFlagExecutor.cpp; PamProviderManagedBlock.cpp. CMake links canonical slot definitions into five standalone verifier fixture targets.
* Regressions: C2 parameter trust/control flow/intent/options, both history variants; ALT legacy transaction apply/no-op/refresh/transient postcondition rollback/foreign preservation/inline conflict; Entry/Flag RollbackFailed; raw structure/identity/ID/semantic refusal and current-byte rollback preservation.
* Authoritative matrix/limits: docs/pam-r1-architecture-research.md §12 and PAM sections of docs/rollback.md. Historical R1/I1/I2 artifacts unchanged. New native-parameter-probe.py tests actual distro libraries, not a replacement parser.

## Validation
* All5 Docker profiles D12/D13/U24/U26/ALT p11: `FIC_PAM_GATE_STAGE=i4 bash tests/integration/pam-dependencies/run-i1.sh TAG PLATFORM BUILD_DIR` → fic +22 test targets built; 24/24 relevant CTest PASS EACH; current production registry audit/Required routing PASS EACH.
* Final before/after source receipts all equal 4cda4231817d12ea17d47bafb5f922371b31c522c5b8269d01e5a26658012522. Final regression binaries checked against stale objects. Evidence: tests/integration/pam-dependencies/i4-evidence.json; raw logs ignored build-pam-i4.
* Five native library/helper parser probes PASS (D/U libpwquality + libpam search_key; ALT libpasswdqc 2.0.3). Four existing native-initial-probe.sh consumer runs PASS: two password changes succeed/reuse rejected. Probe sources unchanged since those successful runs; no unnecessary repeats.
* Harness bash -n, probe py_compile, evidence assertions and git diff --check PASS. Initial stricter comment-edit expectation was superseded by explicit user decision, not classified as a defect. Earlier ALT extra build cache permission failure was infrastructure, repeated gate passed.

## Remaining / limits
* No unfinished I4 work. No full project CTest, full FIC/PAM I6 E2E, package E2E or native ALT history authentication. Parser/helper probes do not prove real authentication.
* ID-only wrappers do not prove historical raw-byte identity. Existing AtomicFileWriter/CAS boundaries against non-cooperating privileged writers remain. No automatic adoption or stronger historical provenance claim.
* U24 exact v1.5.3 source fetch was unavailable; actual installed native helper/parser behavior and production fixtures were checked, not a retrieved exact-source/module-authentication proof.
* Build caches: build-pam-i1/{debian12,debian13,ubuntu2404,ubuntu2604}, build-pam-r1-i3/alt-p11. Images fic-package-native:TAG; ALT fic-pam-dependencies-native:alt-p11. No host PAM mutations.
