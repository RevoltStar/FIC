# Current workspace

## Current base
* Branch `main`; task base `e7acd8b847c95a5e31446df7ad49314fe817105e`.
* Foundation committed as `7f5efab`; apply/REFRESH and safe release core are staged for the second requested commit. Uninstall integration and final evidence remain for the third. No push.

## Current task
* Attachment a18db528: SSH Port ownership across the existing trusted Include graph. Finish five-platform native gates and real packages, then final lifecycle commit. Do not treat this checkpoint as completion.

## Accepted architecture / invariants
* Existing SSH mutex, closure/profile/launch contracts, AtomicFileWriter and MutationJournal only. One durable v3 plan before per-file CAS; no physical multi-file atomicity, blind compensation, adoption or semantic Prepared recovery.
* Main owned Port plus path-bound wrapper creation fingerprints; unchanged wrappers/files retain provenance/inode. Legacy schema2/3 and SSH transitions1/2 retain their meaning; ID-only REFRESH blocked, existing legacy release limitation documented.
* Native `-t/-T` and protected snapshot proof after full publication; bounded pre-CAS graph validation does not claim native validation over target Includes. Unknown/partial publication preserves Prepared and blocks every SSH writer.
* Only explicit Port release permits bounded distinct restored ports; duplicate endpoints remain refused. Scalar contracts unchanged. Uninstall keeps Port until other SSH owners release.

## Completed / changed areas
* Multi-file source map, typed journal plans/receipts and inline proven-no-effect abort; production Port apply/REFRESH, active/offline release, DISABLE acknowledgement.
* Uninstall whole permitted Include inventory (including unused orphan markers/retired paths), alias/staging/generation checks, Port-last resource ordering; these changes remain uncommitted for final lifecycle commit.
* Core unit tests and native multi-file/remote package fixtures expanded. Requested contract docs updated; final evidence/results pending.

## Validation
* Final-source Debian12 full build PASS: `build-ssh-multifile-validation/full-build.log`.
* Full CTest: 216 PASS / 1 FAIL / 4 SKIP, 252.92s. Only failure: known `sssd_i6_evidence_checks` source-generation guard; historical SSSD evidence untouched. Opt-in skips: generic activator native, daemon singleton startup, maintenance preflight, package PAM hooks. Log `full-ctest.log` in same directory.
* Final-source real Debian12 packages/CLI/live-SSH apply, REFRESH, disable, prepare-uninstall, rollback all, remove/purge PASS. Raw report `build-ssh-lifecycle/remote-debian-12-20261103T172609Z-35374/ssh-remote-results.json`. No host security mutations.
* Older-source multi-file42 cases PASS on D12/D13/U24/U26; ALT still running. Final-source five-platform matrix and D12/U24/ALT scalar/legacy regression currently running; do not relabel older-source reports as current.

## Remaining
* Native sessions: D12 64082, D13 9377, U24 70875, U26 34273, ALT 45946; logs `build-ssh-multifile-validation/native-TAG.log`. Runtime containers contain pending reports until runner exports them.
* Regression sessions: D12 19410 (then release and Match), U24 20372, ALT 95708; matching logs in same directory.
* Real package builds: D13 67102, U24 82528, U26 62374, ALT 45430; use existing remote package runner after successful build.
* Source/harness freeze manifests in `build-ssh-multifile-validation/`; verify unchanged after matrix, create concise tracked evidence (no bulk raw JSON/gzip), final docs/HANDOFF, diff review/check and remaining commits. Build logs and raw results are ignored artifacts.
