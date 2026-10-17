# Current working state

## Current base
* Branch `main`, base `798c27a0ea1d310b5de530f925b4a9f7598f889d`; initially clean. One completion commit requested, no push.

## Current task
* Standalone VerifiedConfigServiceActivator, not connected to any existing policy/apply/rollback/startup path. New production files only; tests/CMake and component docs allowed.

## Accepted architecture / invariants
* Already active canonical Type=notify / NotifyAccess=main only; same mount namespace/root as PID1 systemd. Unsupported sandbox/readiness cases fail before mount. READY is the service's initialization declaration, combined with snapshot/observer/final checks, not independent proof of config.
* Bounded private tmpfs, superblock RO, descriptor-based publication, exact manifests and pinned metadata, sticky mountinfo poll, final checks, reverse ordinary unmount. Existing ContentDigest/FileStats/VerifiedProcessExecutor/PlatformExecutableResolver reused.
* Cleanup checks mount ID/object/source before ordinary umount; non-atomic check/unmount race against CAP_SYS_ADMIN explicitly accepted and documented. Cleanup failure never Success; primaryStatus retained.
* Poll is NOT universal: other-namespace remount/fspick pure RO flips produce no event on tested WSL kernel; actual write/read/restore detected by pinned ctime/mtime. No claim of protection against arbitrary CAP_SYS_ADMIN.
* SIGKILL can leave mounts. Next call refuses source-marked residuals; no adoption or startup changes. Docker explicitly approved instead of Podman; no host security mutations.

## Completed / changed areas
* `fic/src/service/VerifiedConfig*`: API, snapshot/mount checks, systemd activation, cleanup and residual detection. No production callers added.
* Unit/API/parser tests, real notify fixture, barrier-driven native race tests and fault injection compiled only into test variant.
* `tests/CMakeLists.txt`, focused native CMake, Docker recipes/runner; `docs/verified-config-service-activator.md`.

## Validation
* Latest native Docker Debian12/13, Ubuntu24.04, ALT p11: 31 PASS / 0 SKIP each, including real mount_setattr, other namespace, fspick, malicious write/read/restore, EBUSY, foreign overlay and SIGKILL. Logs `/tmp/fic-activator-native-{debian12,debian13,ubuntu2404,alt-p11}.log`.
* Debian12 full configure/build PASS; full CTest: 186 PASS, 1 expected native opt-in SKIP, 0 FAIL (187 total), `/tmp/fic-activator-full-validation.log`. Docker unprivileged, DAC override/read-search dropped. All 185 existing tests PASS.

* Exact final source: fic + both new test targets build PASS; related CTest PASS (native opt-in SKIP), `/tmp/fic-activator-final-targets.log`; native matrix repeated after final traversal bound, 31/0 each.
* git diff --check and bash -n native runner PASS; no existing production source changed, no policy callers.

## Remaining / limits
* No unfinished implementation. One completion commit, no push.
* All four userspaces share WSL kernel 6.6.87.2; not separate distro kernels/real boot validation.
* Existing unrelated ALT platform_profile_tests SDDM-path baseline mismatch remains outside scope; full CTest is Debian12.
