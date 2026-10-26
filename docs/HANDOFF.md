# Current workspace

## Current base
* main; task base a8205ea74949bdbdca39f2a86381dcfa6f387db9. Commit1: 810c9b8 (Match semantics). REFRESH is complete in this commit; exactly one final stage3 commit remains. No push.

## Current task
* Attachment167ac2e3: complete SSH verified lifecycle. Continue with verified active release/disable/uninstall + real remote administration. REFRESH completion is not whole-task completion.

## Accepted architecture / invariants
* Same verified engines, closure/launch/executable/RO snapshots/private mount boundaries/CAS/durability/listener-FD proofs. No unsupported Include paths, auto-enablement/start, legacy reload fallback or Prepared auto-recovery.
* User-approved legacy boundary: ID-only wrappers block REFRESH; never derive historical fingerprints from current bodies. Wrapper-free legacy ownership can refresh, same-value compliant legacy apply remains supported. New wrappers bind body at creation. Legacy release remains ID/structure-based and cannot detect valid body edits retaining ID; documented/tested limitation, not silently strengthened/migrated.

## Completed
* Commit1 shared bounded Match semantics/grammar and Include context; all-five native Match matrix 12/12.
* REFRESH schema3 reader accepts schema2 without hash adoption. Existing SSH record keeps previous/target, publication identity/durability/runtime facts and phase. Old permission stays current until atomic finalization. Generic mutators cannot resolve pending intent; clean no-effect abort preserves predecessor, uncertain effects remain Prepared across restart.
* One conditional replacement, retained Port wrapper IDs/historical fingerprints, creation-bound body checks. Shared FileHandler exposes exact unchanged writer serialization. Adapter returns observed runtime identity, not ownership.
* Regression tests cover legacy unchanged/blocked refresh/wrapper-free refresh/release limitation, edited bodies, malformed markers/missing provenance, same-resource gate, publication/runtime/commit/codec/version faults, no-effect abort and SIGKILL windows.
* Authoritative REFRESH contract: docs/ssh-verified-activation-adapter.md; rollback/design docs updated. Evidence: tests/integration/verified_config_service/openssh_native/evidence/refresh-lifecycle.json.

## Validation
* Debian12 full project build PASS; focused five CTest PASS. Final full CTest: 207 registered, 203 PASS, 4 explicit opt-in native skips (188/193/194/199), zero failures. Log build-ssh-lifecycle/refresh-ctest-final-debian12.log. Initial Git safe.directory bind-mount harness error fixed only inside disposable container; no host Git setting changed.
* All five native systemd/OpenSSH profiles: 20 REFRESH/legacy/ownership/fault/crash/current-owner-release groups each PASS. Real Ubuntu listener inode/FD transitions, repeated no-write/no-restart apply, cleanup failure and restart gates asserted. Clean runner/cleanup exit rechecked separately on all five; source never touches host SSH. Logs refresh-{complete,final,release}-*.log; consolidated evidence records composition/infra caveats.
* ALT old 150s aggregate harness limit truncated 21 independent operations; bounded aggregate now scales by <=64 operations, production deadlines unchanged. Positive group measured 263361ms under concurrent load. Earlier live shell-script edits caused trailing token after native PASS; frozen current runner separately exited zero on each profile. Not a product failure hidden as PASS.
* SSH static checks, native harness --self-test, Python/shell syntax and git diff --check PASS. Privileged generic native suites skipped by full CTest are not claimed as run; actual SSH engine exercised in five-profile matrix above.

## Remaining / stage3
* Exact final title: feat(ssh): implement verified active ownership release. Need mandatory remaining ENABLE selections (empty allowed only typed release), native planned-result validation before CAS, same active service/socket engine, distinct proven offline outcome, durable pending-disable intent + fresh registry/config acknowledgement and stale-registry gate, admitted UNINSTALLING target empty without config mutation, real SSH CLI/session/package remove/purge gates on five profiles. Root production release still offline-only Ubuntu/ALT and legacy Debian until stage3 integrated.
* Debian stopped unit removes /run/sshd; current stage2 fixture explicitly supplies native -T prerequisite to test release of refreshed owner. Product offline probe preparation belongs to stage3; do not claim fixture as product fix.
* Parallel temporary worktree /tmp/fic-ssh-release-worktree, detached at 810c9b8. INDEX is REFRESH snapshot; UNSTAGED diff is stage3 only. Do NOT commit staged snapshot there. After root REFRESH commit, export git diff --binary and apply to primary tree; add -N new release_plan_cases.py before export. Review baseline-context conflicts carefully. /tmp/fic-ssh-stage3-integration.md holds provisional integration notes.
* Temp worktree prototypes (not integrated/ready): closed validation-only entrypoint in SAME generic snapshot engine, planned main via existing standardInput/sshd -t/-T -f /dev/stdin and canonical current RO Include inputs, no restart/readiness; typed ConfigurationRelease/empty selections. First seven native active preview cases PASS. Stopped-disabled found GetUnit GC-unloaded units; currently implementing bounded API-bus RefUnit lifetime (atomic load+ref), retaining all authoritative private root-PID1 launch checks. Native confirmation still pending; no start/enable/reload job allowed. Sources systemd v252 dbus-manager.c method_ref_unit, dbus-unit.c sender tracking.
* Temp typed release journal v2/tests PASS mutation_journal_tests: null target, previous state/error preserved, active/offline facts, ReleasedAwaitingDisable and explicit acknowledgement, no generic resolution of uncertain Prepared. Not yet wired to backend/disable/uninstall. Helpers renamed abortSshTransitionNoEffect/failSshTransition only in temp stage3. Native preview Driver action/script present. Caches build-ssh-release-lab/debian12 and build-ssh-release-unit/debian12; release-plan-native-debian12.log / release-journal-unit-debian12.log.
* Finish stage3, import to primary checkout, validate targeted and full Debian12 again + native five-platform active/offline/remote package scenarios. Then create third commit; no push. Do not stop on checkpoint alone.

## Environment
* Docker authorized, DOCKER_CONFIG=/tmp/fic-package-docker-config. Native images fic-ssh-lifecycle-native:{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}; caches build-openssh-native/<platform>. Debian12 production cache build-env-full-debian12, image fic-followup-build:debian12. Guarded loopback-only disposable containers, no host binds/ports in runtime.
