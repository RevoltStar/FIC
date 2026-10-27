# Current workspace

## Current base
* Branch main; task base a8205ea74949bdbdca39f2a86381dcfa6f387db9.
* First commit: 810c9b8f7c40f1e54596d7016cbe3ccc15403210 (Match). Second: 670e85afe9299d3f413d1dac291abd8e16d4b7aa (REFRESH).
* This snapshot belongs to the third/final `feat(ssh): implement verified active ownership release` commit. No push.

## Current task
* Attachment167ac2e3 SSH lifecycle completed: shared Match semantics, safe owned REFRESH, verified active/offline release, disable ACK and actual SSH/package administration on five profiles. No unfinished implementation stage remains.

## Accepted architecture / invariants
* Same engines, closure/launch/executable/RO snapshot/private mount boundaries/CAS/durability/listener-FD proofs. No auto-install/enable/start SSH, legacy reload fallback, arbitrary Includes/overrides, multi-file Port wrappers, adoption or uncertain Prepared semantic recovery.
* Legacy ID-only wrappers block REFRESH; no historical fingerprints synthesized. Wrapper-free legacy REFRESH and compliant same-value apply supported. New wrappers bind body at creation. Legacy release deliberately remains ID/structure-based and cannot detect valid body edits retaining ID.
* ConfigurationRelease validates all remaining ENABLE SSH requirements before CAS (uninstall target empty). Known error-free released_awaiting_disable permits explicit repeat/reproof/ACK only; uncertain phases remain fail-closed.

## Completed / changed areas
* Shared Match semantics and Include context; REFRESH schema3 accepts schema2 without adoption, retains previous/target/publication/runtime and monotonic operation sequence. One conditional replacement, no preliminary ownership release; uncertain effects remain Prepared.
* SshRollback/adapter/runtime: planned native -t/-T stdin image proof under same snapshot before CAS; active verified platform flow and separate no-start offline result. Fixed-unit RefUnit holds stopped units without start jobs; API bus pinned to root PID1 manager, authoritative launch checks retain direct private bus.
* Journal release transition v2: previous permission, null target, replacement fact, publication/durability/runtime and predecessor. Durable DISABLE→registry rebuild→reproof→typed ACK; stale Policy objects cannot recreate ownership. UNINSTALLING uses same backend and preserves configuration.
* Existing low-level restore/durability helpers moved unchanged into SshConfigTransaction so narrow runtime tests need no full rollback engine.
* Actual ALT RPM gate found UI ru_RU locale broke mountinfo numeric extraction. Parser uses classic locale; deterministic regression and real daemon RPM/SSH E2E pass. Mount grammar unchanged.
* Successful CLI disable now reports RuntimeVerified without stale awaiting-ACK text. Explicit regression in actual package gate on all five profiles.
* Authoritative contract: docs/ssh-verified-activation-adapter.md. Platform/rollback/design docs and native README updated. Sanitized case/runtime/journal/listener/package evidence: tests/integration/verified_config_service/openssh_native/evidence/{match-lifecycle,refresh-lifecycle,release-lifecycle}.json.

## Validation
* Final Debian12 full project build + CTest PASS: 207 registered, 203 PASS, 4 explicit opt-in SKIP (188 verified_config_service_native_tests, 193 daemon_singleton_startup_native, 194 maintenance_preflight_native, 199 package_pam_hooks_native), zero failures. Log build-ssh-lifecycle/release-full-cli-debian12.log (110.60s). Includes journal/rollback and other backend regressions. Earlier full runs also passed; repeat after locale/CLI edits ensured final objects rebuilt. Skips are not native PASS.
* All five profiles: Match12/12 and REFRESH20 groups each PASS in prior commits. Release30 groups each PASS: Debian12 separate successful positive5/negative20/admission5; Debian13, Ubuntu24/26, ALT all30 successful complete runs. Debian12 preview8/8 PASS. Native release fault binaries preceded final diagnostic-only string deletion; control flow unchanged, final full CTest and all real package gates reran after it.
* Actual final packages/daemon/CLI/IPC and one preauthenticated loopback SSH ControlMaster: PASS on Debian12/13, Ubuntu24/26 and ALT p11. Disable root, MaxAuthTries REFRESH, real Port change, prepare-uninstall/rollback all, actual remove; four DEBs also purge. No reconnect allowed, vendor unit unchanged, configuration unchanged by rollback/remove. Logs release-remote-cli-*.log; newest PASS remote-*/ssh-remote-results.json under build-ssh-lifecycle identifies final archive SHAs/proofs. ALT derivative adds only test SSH client, no production dependency.
* Ubuntu failed-service test originally left Result=failed and started only socket for next scenario; FIC correctly refused before mutation. Fixture now explicitly starts valid service after native limit interval if Result failed; both full suites rerun PASS. ALT native Driver uses actual ru_RU matching daemon. No production start/reset-limit relaxation.
* SSH static checks, harness --self-test, shell/Python syntax and git diff --check PASS. Runner zero exits and host before/after guard verified.

## Remaining / limits
* No unfinished task work. No push. Unknown publication/runtime/journal/cleanup/failed reproof retains unresolved Prepared and requires manual resolution. Known explicit disable ACK is not automatic uncertain recovery.
* Five userlands share Docker/WSL kernel. Test fixtures prepare private mount boundaries/trust/udev readiness only in disposable containers. Real host shared-root boundary provisioning remains deployment work. Stock KillMode=process loopback-session survival is not an arbitrary network/custom topology guarantee. Legacy ID-only body limitation remains explicit.
* Do not use stale /tmp/fic-ssh-release-worktree; implementation and commits are in /home/admsys/FIC.

## Environment
* Docker authorized; DOCKER_CONFIG=/tmp/fic-package-docker-config. Runtime containers use network none/loopback only, no host binds/ports or host security mutations.
* Native images fic-ssh-lifecycle-native:{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}; caches build-openssh-native/<platform>, separate Debian12 build-ssh-release-lab/debian12. Full Debian12 cache build-env-full-debian12.
* Package caches build-package-release/<tag>, Debian12 full cache/ssh-release-packages; ALT lifecycle-packages + remote image fic-ssh-release-remote:alt-p11. Raw build/native/package logs in ignored build-ssh-lifecycle; consolidated source-controlled evidence is authoritative bounded summary.
