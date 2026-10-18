# Current working state

## Current base
* `main`, `0a87a928e41ca9d37084b9c81bc4371be8f99eb9`; initially clean. One implementation commit requested; no push.

## Current task
* Completed Verified EnvironmentFile v1 in standalone activator. No integration with policies/SSH/transactions/ownership/journal, no unit/trust-store lifecycle changes.

## Accepted architecture / invariants
* B on existing A: internal typed `EnvironmentFiles a(sb)` coverage classifier + existing single bounded tmpfs/RO/bind/observer/cleanup lifecycle. Public API/statuses unchanged.
* Every loaded entry needs exact explicit File target with reference SHA. Keep order/optional flags/duplicates in pinned contract; one target can cover repeated path. No directory-only implicit coverage.
* Existing optional-present supported; absent/glob/symlink/non-normalized/unresolved-specifier/nonregular/unsafe metadata/mount topology refused before first own mount. No context still rejects nonempty EnvironmentFiles.
* Same namespace/root, root PID1 D-Bus, trusted systemctl, private/non-shared parents/workspace, notify/new invocation, strict observer and identity-safe cleanup retained. Shared-root deployment boundaries remain external prerequisite.
* Accepted privileged-adversary/alternate-namespace observer/contract ABA/check-bind/check-umount residuals retained; SHA bytes do not prove SSH options/Include semantic safety.

## Completed / changed areas
* LaunchContract classifier; SystemdActivation keeps request targets internally and compares full canonical launch properties throughout activation. Activator verifies all targets before mounting and rechecks envfile SHA before bind alongside existing identity CAS.
* D-Bus ETIMEDOUT now remains TimedOut (not falsely InterferenceDetected). Unit classifier negatives for missing/malformed schema/paths/coverage; actual production native suite extended with env/argv/config FD mount/SHA/PID/InvocationID, Condition/Pre/Post, races/failures/cleanup/residuals. Existing negative suites retained.
* Native runner accepts Ubuntu26 and waits for PID1 initial boot jobs before tests (first un-settled Ubuntu26 run correctly failed strict observer). Fixture service readiness still actual notify, no sleep fallback.
* `docs/verified-config-service-activator.md`: v1 contract, scope, matrix and security review.

## Validation
* Final native matrix `bash tests/integration/verified_config_service/run-native.sh fic-ssh-audit:<tag> <profile>`: Debian12/13, Ubuntu24.04/26.04, ALT p11 all 91 PASS / 0 SKIP; logs `build-verified-config/logs/*-env.log`.
* All five userspaces share 6.6.87.2-microsoft-standard-WSL2; not separate distro kernels/VM. No stock SSH commands/config/units modified.
* Existing cross-namespace no-write RO flip remains measured observer blind spot; writes detected by final metadata checks. All normal/fault env scenarios verify no residuals; foreign/crash cleanup only explicit fixture admin.
* Bash syntax and git diff --check PASS so far.
* Full Debian12 configure/build PASS on final sources; full CTest 186 PASS / 0 FAIL / 1 expected native opt-in SKIP (187 total, 218.05 s). Actual `verified_config_service_tests` PASS; privileged native matrix performed separately, not inferred from skip.
* Final full command: Docker `fic-ssh-audit:debian12`, no network, source read-only, own writable `build-env-full-debian12` volume; `cmake -S /src -B /build -DFIC_TARGET_PLATFORM=debian-12; cmake --build /build -j6; QT_QPA_PLATFORM=offscreen ctest --test-dir /build --output-on-failure`. Log `build-verified-config/logs/full-debian12-nodac.log`.
* Full CTest container drops DAC_OVERRIDE/DAC_READ_SEARCH (chmod fault tests need real denial), safe.directory=/src only inside disposable container. Earlier default-root permission failures were reproduced/pass without bypass using the SAME MutationJournal binary; no unrelated code/test changes. Own build-root ownership restored by EXIT trap.

## Remaining / limits
* Requested implementation/validation complete; one implementation commit over base, no push. No policy integration in this task.
* NOT_TESTED: VM/physical distro kernels, actual SSH, enforcing SELinux/ACL provider semantics. Optional-absence/glob/symlink support, private-boundary deployment, Ubuntu sockets/ALT notify and SSH adapter semantic closure are intentionally separate future tasks.
* Generic activator still trusts service READY semantics and caller input closure; known CAP_SYS_ADMIN/namespace/contract ABA limitations remain. No second snapshot engine, placeholder, managed unit or automatic crash adoption added.
