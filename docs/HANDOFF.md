# Current workspace

## Current base
* main; base a8205ea74949bdbdca39f2a86381dcfa6f387db9. New task requires exactly three sequential commits, no push.

## Current task
* Attachment167ac2e3: complete SSH lifecycle. Commit1 Match semantics; commit2 crash-consistent verified REFRESH; commit3 verified active release + disable/uninstall/native remote administration. Continue to completion; stage1 is not task completion.

## Accepted architecture / invariants
* Existing verified closure/launch/executable/RO snapshots/mount boundaries/CAS/durability/listener-FD proofs stay strict. Only distro /etc/ssh or ALT /etc/openssh boundaries; no external Include or automatic directory/provider/service enablement. No Prepared auto-recovery.
* User explicitly chose legacy compatibility boundary: ID-only wrappers block REFRESH; never infer historical fingerprints from current bodies. Wrapper-free legacy ownership may refresh; unchanged compliant apply must not fail just for legacy format. New wrappers capture fingerprints at creation. Legacy release remains ID/structure-based (cannot detect valid body edits preserving ID); document/regression-test, do not silently change it.

## Completed (first commit)
* Shared SshPolicySemantics conditional order and full bounded Match criteria grammar; global selected values stay exact. Runtime/audit/closure use common mechanism. Closure copies Match context into each Include; restores caller/sibling context on return (native OpenSSH confirmed).
* Unit table + native match_cases.py uses actual sshd -t/-T and real verified engine. Source-list linkage for UnrecordedResourceInspection in shared SSH test source list corrected (base omitted it). Production non-SSH policy behavior preserved, including exact PAMServiceName verifier.
* Native test images add readonly sys/proc-sys and mask coldplug, not SSH vendor units. ALT test-only ctest package required. Match runner reads typed StartLimitIntervalUSec and waits per independent fixture; never resets/weakens limits.
* Docs common/ALT/Debian/design and evidence/match-lifecycle.json updated.

## Validation
* Debian12 fic and SSH runtime/verified adapter/apply-rollback/rollback executor targets built, 4/4 focused CTest PASS.
* Final native Match matrix: 12/12 cases PASS on Debian12/13 Ubuntu24/26 ALT p11. Safe nested/stricter/synonym inputs activate; weak/global-only/external/unknown grammar refuse. Native runtime reports actual A/C/P, readiness/cleanup, syntax and selected -T-C values; host SSH bytes unchanged.
* Python/shell syntax and git diff --check PASS. Raw build-ssh-lifecycle/match-final-*.log; build-openssh-native/<platform>/evidence/match-results.json. No full build/CTest yet (required on Debian12 at final completion).

## Remaining / next actions
* Implement commit2 and commit3; no production REFRESH/active release changes yet. Journal currently schema2, apply refuses value changes/reprepare; Ubuntu/ALT release requires offline, Debian release still legacy reload.
* Read /tmp/fic-ssh-refresh-design.md for investigated integration points/implementation plan (provisional design, not completed code). Prefer minimal schema3 typed previous/target transition in existing SSH undo payload with durable phase/effect/runtime facts; keep old appliedValue until verified atomic finalization. Read schema2 without adopting legacy wrapper bodies. Validate/gate direct mutators, preserve Prepared on uncertain effects, safe no-effect abort preserves old permission.
* Commit3 needs native pre-CAS validation of resulting planned image and all remaining enabled policies, typed ConfigurationRelease (empty selections allowed only there), verified active/offline distinction, durable pending-disable intent so config save/reload failures cannot resurrect released ownership. Coordinate PolicyDisableFlow/RollbackExecutor generic status updates. Do not add automatic Prepared recovery.
* Required final native five-platform apply/refresh/disable/active rollback/session continuity + package gates, fault/crash/journal regressions and full Debian12 build/CTest. Current stage1 evidence is not those guarantees.
* Docker authorized. Images fic-ssh-lifecycle-native:{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}; ALT base fic-ssh-lifecycle-build:alt-p11. Existing 4 DEB build images/caches remain. Native runner profile caches build-openssh-native/<platform>. DOCKER_CONFIG=/tmp/fic-package-docker-config avoids unavailable credential helper. No host SSH changes.
