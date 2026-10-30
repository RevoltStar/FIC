# Current workspace

## Current base
* main; task base e36904b7572394de1c728713b154eb5b6236b919. This snapshot belongs to the single `feat(sssd): implement verified service activation adapter` completion commit. No push.

## Current task
* I3 (attachment 77b86872) completed. Do not start I4 automatically.

## Accepted architecture / invariants
* User accepts bounded source-causal C, not direct memory/every consuming path execution: concrete consumer↔protected graph/ConfigDB generation, versioned initialization and readiness are mandatory. No production auth, memory instrumentation or SSSD hooks.
* Existing generic engine only; SSSD-specific notify/PIDFile/validator profile, exact empty-directory manifest and conservative activation-dispatch evidence. Generic/SSH PIDFile, environment, mounts, observer and cleanup guarantees remain.
* Full /etc/sssd parent protects missing main/conf.d. Missing EnvironmentFile outside it is Unsupported, never fabricated by adapter. Already-active service, private deployment boundaries and prepared native metadata required; no foreign chmod/chown.
* Old 2.8/2.9 backend monitor connection follows dp_init_recv. Modern 2.10/2.12 requires read-only central-bus unique-owner/PID binding and IsOnline interface installed after dp_init targets. SO_PEERCRED identifies the new monitor; socket peers, ConfigDB FD/shared mapping, pidfd/start/executable/credentials/cgroup/namespace and native code are rechecked. Do not replace this with responder birth order or READY alone.
* Runtime state ancestors are no-symlink root/native-service controlled; unsafe writable directories/access/default ACLs are refused. ldbsearch receives only a bounded private memory copy; live ConfigDB is read-only and generation rechecked.
* Configured monitor-spawned PAM + SCM_CREDENTIALS GET_VERSION only; selected lazy-only PAM remains Unsupported. C excludes actual login success, future LDAP health and periodic cleanup execution. Exact researched package revisions/tools must already be trusted; no automatic provisioning.
* P compares persistent sources independently of old monitor PID. Separate final runtime recheck can invalidate B/C while P remains Proven. Cleanup/primary/runtime uncertainty stay separate; no policy SUCCESS, ownership, journal, release or package lifecycle authority.

## Completed / changed areas
* New service/sssd/SssdVerifiedActivationAdapter and SssdRuntimeProof; narrow generic additions and read-only I1 helpers. Existing SSSD policies/runtime/rollback, MutationJournal and package lifecycle untouched.
* Dedicated unit/contract target, native test-only hooks and complete isolated sssd-i3 runner/evidence/source review. Source manifest captured before build and compared after run; completion requires successful execution and exact input hashes. Native reports exported through exec, not Docker archive view of systemd /run.
* R2 LDAP/TLS/PAM fixture reused unchanged; only synthetic users/credentials and disposable containers. No stock SSSD unit replaced. ALT stock absent EnvironmentFile refusal is separate from explicit native environment positive fixture.
* OverlayFS mmap object proof uses kernel map_files stat. Preserved Ubuntu26 getty credential-mount strace/refusal; only unrelated fixture getty quiesced, observer not weakened.
* Historical R1/R2/I1/I2 evidence bytes unchanged. Their guards read exact accepted historical Git snapshots; current I1 regressions retained separately. CI test/sanitizer jobs fetch full history; safe.directory is per Git invocation only.

## Validation
* Production `fic fic-cli fic-gui` and affected test targets build PASS in Debian12 fic-sssd-i1:full builder; current logs build-sssd-i1/full/i3-final4-{build,tests}.log, configure i3-configure.log.
* CTest PASS17/17 (1.32s): new I3 unit/evidence; I1/I2 unit/evidence; R1/R2 guard; SSSD uninstall; generic/SSH verified/static; prelogin/desktop package checks; package trust/state/release/uninstall. Ordinary CTest never launches Docker.
* Existing identity_configuration_editors_tests, identity_concrete_policies_tests, ssh_runtime_tests, ssh_apply_rollback_tests build and CTest PASS4/4 (15.16s). Logs build-env-full-debian12/i3-regression-{build,tests}.log.
* Final native matrix exit0 on all five, source-bound completion manifests: 55 observations Debian12/Ubuntu24; 57 Debian13/Ubuntu26/ALT. Positive A/B/source-causal-C/P, clean cleanup, two LDAP roots, missing main/conf.d, four further adapter activations with real synthetic LDAP/PAM functional checks; all mandatory unit/snippet/FD/topology/SIGSTOP/stale-ConfigDB/consumer/cleanup/persistent faults. Modern unsafe state-parent/foreign-ACL rejection before dispatch included. Logs /tmp/sssd-i3-final4-*.log, raw build-sssd-i3/<platform>/native.
* Current I1 native reruns exit0: 43 observations per Debian/Ubuntu, 58 ALT. Separate i1-regressions.json/reports, historical evidence not rewritten.
* collect-evidence.py/check-evidence.py, historical evidence guards, Python AST/bash syntax and git diff --check PASS. Authoritative versioned results: tests/integration/sssd-i3/{evidence.json,i1-regressions.json,reports/,source-review.json}; diagnostics retained separately. All task containers removed, including causal research container; source file ownership restored after formatting.

## Remaining / limits
* No unfinished I3 implementation. No full unrelated all-project CTest, native SSH runtime/package-manager E2E rerun, bare-metal/enforcing-LSM/Podman/other-architecture certification. Targeted SSH/SSSD/package regressions passed; native adapter compiled/executed on all five, full daemon/client targets built on Debian12.
* Stock ALT with absent /etc/sysconfig/sssd is Unsupported; positive fixture explicitly configures it. Lazy-only selected PAM and unknown package revisions/providers/topologies remain Unsupported. Root/native service/code/tool trust and finite observation-window limits remain explicit.
* I4: trusted ownership context, journal/CAS mutation, Apply/REFRESH/crash recovery. I5: verified ownership release/rollback. I6: policies/dependencies/CLI/GUI/end-to-end integration. No I3 runtime proof work deferred to those stages.
