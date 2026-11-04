# Current workspace

## Current base
* Branch `main`; task base `e7acd8b847c95a5e31446df7ad49314fe817105e`.
* Foundation `7f5efaba9415c9eaff90c09b690b198c6b096f60`; apply/REFRESH and safe release core `b9a744a8e588c83a426da905ccb6f5b1e152b254`. This final lifecycle commit completes attachment a18db528. No push.

## Current task
* Completed multi-file SSH Port ownership across the existing trusted Include graph, including verified release, disable and package uninstall.

## Accepted architecture / invariants
* Existing SSH resource mutex, profile/closure/launch boundaries, AtomicFileWriter and MutationJournal. One durable SSH v3 plan before separate per-file CAS; no physical multi-file atomicity or blind compensation.
* Main owned Port plus per-path wrapper IDs and creation fingerprints. REFRESH preserves established provenance and unchanged file identities. Missing artifacts are not reconstructed/adopted.
* Pre-CAS bounded structural validation; native `-t/-T`, protected RO input snapshot and actual runtime proof after complete publication. Partial/unknown effects retain Prepared and block all SSH writers; no automatic semantic recovery.
* Inline no-effect abort requires direct NotInstalled observations in that attempt. Historical schema2/3 and SSH v1/v2 remain readable; ID-only REFRESH refuses, historical ID-only release limitation remains documented.
* Only explicit Port release accepts bounded distinct restored ports; duplicate endpoints/unsupported ListenAddress remain refused. Uninstall releases Port after other SSH owners and scans the whole permitted Include inventory for physical orphan artifacts.

## Completed / changed areas
* SSH source mapping, typed journal plan/receipts and Port apply/REFRESH coordinator.
* Verified active/offline release, all-file DISABLE acknowledgement, final uninstall physical proof and resource ordering.
* Unit/native/real package fixtures and requested contract documentation. Authoritative contract: `docs/ssh-verified-activation-adapter.md`, multi-file Port section.

## Validation
* Final-source Debian12 full build PASS. Full CTest: 216 PASS / 1 FAIL / 4 SKIP (221 total, 252.92s). Only failure: known `sssd_i6_evidence_checks` historical source-generation mismatch; guard/evidence untouched. Skips: generic activator native, daemon singleton startup, maintenance preflight, package PAM hooks.
* Native Docker/systemd/OpenSSH: Debian12/13, Ubuntu24.04/26.04, ALT p11 each PASS multi-file42 (90 module operations) plus initially-compliant ownership9. Includes CAS/checkpoint/durability/cleanup faults, crash/restart shared gate, aliases/trust boundaries, active/offline release, exact EOF preservation and foreign edits.
* Additional scalar/legacy/REFRESH regression21 PASS on Debian12, Ubuntu24.04, ALT p11; Debian12 verified release30 and Match12 PASS.
* Actual packages/production daemon/CLI/IPC/live SSH: all five platforms PASS apply, REFRESH, disable, re-enrollment, prepare-uninstall, rollback all, remove/purge; original authenticated control connection reused, no fallback reconnect, Include wrappers absent after release. ALT expected fixture stop diagnostic: absent ssh.socket; production operations succeed.
* Frozen production/build and harness manifests unchanged across final matrix. Compact source/ELF/package/image/raw-report bindings: `tests/integration/verified_config_service/openssh_native/evidence/multifile-port-lifecycle.json`. Raw logs/results stay in ignored `build-ssh-multifile-validation`, `build-openssh-native` and `build-ssh-lifecycle` directories; no compressed report blobs committed.
* Python syntax and final diff checks PASS. Host security configuration untouched; all runtime mutation in disposable containers.

## Remaining / limits
* No unfinished implementation for this task. Full CTest retains the explicitly allowed stale SSSD evidence failure; this task does not refresh unrelated SSSD evidence.
* Existing private mount/closed launch prerequisites and CAS residual race against noncooperating privileged writers remain. External privileged restart during partial publication is not excluded by FIC locking.
* Missing recorded files, modified wrappers and unsupported restored endpoints fail closed. Named Port service aliases remain unsupported; numeric syntax includes leading +/zeros within the existing line bound.
* Legacy ID-only rollback cannot detect body replacement with a retained ID; its semantics were not silently strengthened. Such wrappers cannot REFRESH without historical fingerprints.
* Native matrix shares a WSL kernel; no independent five-kernel, real-host boot or GUI click validation claimed.
