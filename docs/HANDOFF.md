# Current working state

## Current base
* `main`; SSH classifier substage see `git log -1`; profile/admission primitives see git log -1; previous `534a0ad`, initial task base `d8bc274`. No push.

## Current task
* Attachment `da117094-3d53-47b9-ae43-ed5a943d3347`: Debian12/13 SSH supported boundary and verified policy end-to-end. **Not complete: A profile implemented locally; B adapter primitives implemented, policy integration still pending.**
* Supersedes active M1 work. M1 must remain frozen; do not bypass fence or synthesize Installed to test SSH.

## Accepted architecture / invariants
* Native Debian ssh.service/sshd alias, /usr/sbin/sshd, config main + `.d`, default SSH env/HostKeys. Detect unsupported configurations, no automatic repair/ownership adoption.
* Whole recursive Include graph, including empty globs and conditional Includes; exact directory negative manifest. Selected-policy Match assignment conservatively unsupported; unrelated Match may pass native syntax/semantics check.
* Enabled AND proven-ready runtime before writes; bounded waits only for already pending/recovering systemd startup; no enable/start/unmask. Recheck after save/before activation/final proof.
* Reuse generic activator/internal engine entrypoint, typed launch proofs, existing CAS/MutationJournal/R1/R1b/R5; no schema/global lifecycle redesign or blind restore/Prepared recovery.
* Ubuntu24/26 Unsupported for new strict policy path (future socket activation task); ALT behavior preserved. No Debian fallback on Ubuntu.
* Runtime receipt may be in-memory, tightly bound to boot/unit/invocation/PID/launch/full reference/policies; no repeated unnecessary restart. No unbounded watcher or privileged ABA guarantees.

## Completed / changed areas
* First partial A classifier substage in SshVerifiedInputClosure: pattern boundary checked BEFORE expansion, only `.d` Include (relative resolves from /etc/ssh). Even caller-protected external directory cannot expand authority. Existing recursion/limits/manifests retained.
* Closure now requires selected policies, production adapter passes them. Match first criterion limited to all/User/Group/Address/LocalAddress/LocalPort/Host; selected conditional directive assignment refuses. Textual Match context shared across Include traversal, conservative; native sshd remains syntax/effective authority.
* Unit regressions added: unrelated Match accepted, relevant included assignment refused, different selected policy independent, relative in-bound Include, nested/conditional external empty-glob refusal.
* Native `openssh_native/boundary_syntax.py` validates real OpenSSH Match syntax/context ONLY; explicitly NOT verified apply/restart evidence. Source Python globally ignored, force-add required.
* Adapter/lifecycle docs record implemented partial substage and remaining integration; historical v1 audit remains historical.

## Validation
* Current profile/admission changes: complete default HostKey set and quoted/unquoted empty options; narrow source-fingerprinted Description/CPUWeight drop-ins; typed UnitFileState observation, persistent-enabled requirement for SSH only, bounded pending-runtime admission, post-cleanup promoted PID/invocation/readiness proof. No policy apply integration yet. New header SshServiceAdmission.h classifies states, implemented by existing adapter TU.
* Builds fic/SSH/generic targets + 7 related CTest PASS (7.95s then 6.88s): ssh-launch-enablement-tests.log / ssh-admission-tests.log. Initial missing ContentDigest include fixed. Earlier MutationJournal failures were harness DAC_OVERRIDE, fixed by dropping DAC capabilities, repeated GREEN.
* Real Debian12/13 OpenSSH suites GREEN after default-key fixture duplicate corrected: ssh-profile-native-debian{12,13}.log, stock unit bytes unchanged, restored sshd -t. Added native actual adapter default HostKeys, unrelated Match, compatible administrative drop-in; existing generic/fault suite retained. Final reruns after bounded admission/capture ordering GREEN in ssh-profile-final-native-debian{12,13}.log. Native disabled-active/disabled-inactive/enabled-inactive-no-Job and persistent-input equality cases GREEN in ssh-admission-final-native-debian{12,13}.log. Driver instrumentation GetUnit on GC inactive unit originally preempted adapter; fixed to record optional probe failure and always call production adapter, repeated GREEN.
* Generic native other distro regressions: Ubuntu24/26 202 PASS each; ALT201 PASS/1 SKIP (stock lower-layer empty SSH Include copy-up fixture unavailable): ssh-generic-regression-{ubuntu2404,ubuntu2604,alt-p11}.log.
* Full D12 configure-cache/build + CTest GREEN 204 PASS/6 SKIP, 191.45s: ssh-profile-full-debian12.log. This run did not opt into M1 singleton/preflight native gates; skips 187/192/193/205/209/210. No complete module/policy verified apply/native receipt/fault matrix yet.
* Docker D12: `cmake --build /build --target fic ssh_verified_activation_tests -j6` succeeded. Initial unit exposed unsupported Match exec acceptance; fixed limited first-criterion allowlist, repeated GREEN.
* SSH runtime/apply-rollback/verified, generic activator, MutationJournal and native-harness contract: 7 CTest PASS in `build-m1-evidence/ssh-boundary-related.log` (6.82s); narrower 2 SSH CTests PASS in `ssh-boundary-tests.log`.
* Real OpenSSH Debian12/13 `sshd -t/-T -C`: unrelated User backup/X11Forwarding accepted, conditional PermitRootLogin override effective; `ssh-boundary-syntax-{debian12,debian13}.log` PASS. Fresh network-none Docker containers only, no host SSH/PAM/network changes.
* git diff --check PASS. Full build/full CTest for whole new task NOT yet run; previous M1 baseline full D12 206 PASS/4 expected SKIP (210) is NOT current SSH task completion evidence.

## Remaining / next actions
1. A native adapter positive defaults/Match/drop-ins now implemented/tested; remaining task full boundary negative/native matrix and SshConfigAudit review/integration to share supported boundary BEFORE writes. Profile substage is not whole policy integration. No blanket release/rollback change.
2. B adapter primitives implemented; still need integration before policy writes/after durable save, complete deterministic native state/race matrix. Rollback ownership release must remain independent of apply admission. enabled-runtime currently Unsupported, only persistent enabled accepted.
3. C: trusted production reference builder and real policy apply -> adapter integration, no-op receipt, serialized SSH resource mutex + unresolved Prepared gates where required, saved/runtime/drift/cleanup/journal outcomes without blind compensation. No new schema.
4. D: actual systemd PID1/OpenSSH Debian12/13 module integration runner (M1 blocks full daemon startup), complete task positive/negative/fault/race matrix, existing native suite and generic cross-distro regressions, full D12 build/CTest. Then write separate Ubuntu socket activation specification/TODO.
* Read original attachment for complete acceptance criteria; do not treat classifier/native syntax probes as end-to-end PASS.

## Frozen M1 / environment
* M1 incomplete at d8bc274; accepted legacy admission contract cannot be implemented by dependency declarations alone. See maintenance-legacy-compatibility.md / maintenance-runtime-package-design.md / maintenance-finalizer-retry-lifecycle.md, AGENTS §17. No accepted extra per-transaction admission architecture; no preparatory migration authorized.
* Existing package scripts NOT switched; no full configure/recovery/finalizer/runtime split. Daemon strict fence admission remains. Do not repair/bootstrap M1 for SSH.
* Docker images fic-ssh-audit:{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}; build-env-full-debian12 one writer only, source /src RO + /build RW. Full tests use git safe.directory /src, DAC_OVERRIDE/DAC_READ_SEARCH dropped, QT_QPA_PLATFORM=offscreen.
* Five fic-m1-masks-* fixtures may contain private Installing fences/masks. D12 contains dummy fic-runtime old real ELF + entrypoint fixture and canonical Installing state; NOT clean SSH test environment. Prefer fresh disposable native SSH runner; don't clear those fences manually.
* build-m1-evidence logs ignored, preserved across reboot. fic-m1-rpm-order:tooling is dummy RPM tooling cache, not actual FIC install.
