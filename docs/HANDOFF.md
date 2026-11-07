# Current workspace

## Current base
* main; base `8a1c24bc0c356a908230a6e2e406b04f20651a22`.
* R1: `e5c2798d961afa791b6568dfc10b25d1f5ae9816`. I3 is the second task commit; no push.

## Current task
* Attachment a6a92742: R1 research + I3 Required PAM dependencies completed. No additional PAM stages authorized.

## Accepted architecture / invariants
* Every registered supported/read-only option has one canonical Required activation. Activation registration follows actual option capabilities, not a representative feature.
* Structural only; ALT passwdqc StaticVerifyOnly gains registration, not a writer or ownership. Preserve Recommended disable_nopasswdlogin, C2 joint Q/H, ALT blocks, provider rollback and package lifecycle.
* R1 evidence remains historical. No host PAM mutation; Docker authorized.

## Completed / changed areas
* R1 report and registry/control research committed; authoritative bounded findings: docs/pam-r1-architecture-research.md.
* I3 production changes only PamOptionPolicy.cpp and daemon/main_function.cpp.
* Actual registry/planner/disable/ReadOnly/missing-ref/foreign Structural/no-mutation contracts in tests/integration/pam-dependencies. Provider rollback regression proves release independent of effective activation. Platform static check and CMake updated.
* Existing wiring supportContract corrected for ALT StaticVerifyOnly/AltTcbManaged; no production support change.

## Validation
* Before disk cleanup: fic +10 test targets built all5; D12/D13/U24/U26 each12/12 CTest PASS. D12 Driver also PASS uid65534. U24 Docker wrapper exit125 AFTER successful CTest/audit due storage I/O.
* User deleted raw logs/build receipts/images. Successful D/U tests not repeated as requested. Do not claim recovered historical hashes or final revised wiring-test binaries on D/U.
* Fresh ALT image and10 targets built; initial9/10 PASS, existing wiring test expectation fixed; only failed suite rebuilt/rerun1/1 PASS. Actual registry audit PASS;12 options/36 planner cases. Fresh hashes/contracts/audit in i3-evidence.json.
* Generic packaging/platform static checks and harness syntax passed before cleanup; git diff --check passed at completion.

## Remaining / limits
* No unfinished I3 implementation. Full functional authentication/password-change/package-manager E2E and native ALT libpasswdqc-devel probe not run.
* R1 follow-ups intentionally outside I3: ALT block MutationId/physical ownership ambiguity, broader control modes/foreign topology, enforcement redesign and unrelated stale comments. See report §8.
