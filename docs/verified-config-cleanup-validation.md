# Verified cleanup retry validation — 2026-11-16

Base: `50a60c3d6a7717a11ad0f4c21cbf373ec43b0ce9`.
Contract: [verified-config-service-activator.md](verified-config-service-activator.md).
Production change is confined to `Operation::cleanup()` and its `<thread>` include.
Existing cleanup diagnostics, primary status, proofs, ownership and journal remain.
No remote machines or real KESL were accessed for this implementation task.

## Executed gates

* Local production `fic`, `verified_config_service_tests`,
  `ssh_verified_activation_tests` build PASS (`build-startup-classification`).
  Final targeted CTest **2/2 PASS**. Initial sandbox-only SSH unit run could not
  enumerate local addresses; rerun with read-only netlink access PASS.
* Debian12 real systemd generic Docker native suite: **220 PASS / 0 SKIP**,
  including all prior private/shared, downstream topology, namespace, foreign
  identity, environment, crash/residual and actual notify consumer cases.
* Focused real OpenSSH policy/adapter suite: **7/7 PASS**, including persistent
  Logger→journald/Prepared, transient apply, transient read-only snapshot,
  transient active release and persistent snapshot/release diagnostics.
  Its SSH unit gate also PASS (1/1).
* Existing release-plan Docker suite: **9/9 PASS** (active/offline planning,
  syntax guards and persistent snapshot-cleanup diagnostic).
* Python syntax, final diff review and `git diff --check` PASS.

## T1–T9

Native counters are observed immediately before ordinary umount in the existing
fault callback, which returns **0** in real-FD cases. The retry is reached only
following an actual kernel EBUSY. These cases are not errno injection tests.
The controlled child opens the publication, closes unrelated inherited FDs and
acknowledges HELD. It cannot close the held FD until the parent signals after
observing the next cleanup attempt. Only then does its150/350ms timer start.

| Test | Result | Evidence / assertions |
| --- | --- | --- |
| T1 transient | PASS | Actual other-process FD. Published file7 attempts, workspace1; cleanup406ms, primary/final Success, no cleanupErrors/residuals. |
| T2 persistent | PASS | Actual held FD outlives5s cleanup.52 attempts, single target error/residual, stage=umount2, errno16, retry-deadline diagnostic. Existing cleanupCases also checks repeat invocation refuses residual adoption. FD released only after result; separate fixture cleanup succeeds. |
| T3 multiple | PASS | Actual directory/file holders: directory5 attempts, file7, workspace1; total410ms, no remaining mounts. With one persistent holder: directory5, file52, workspace1; total5002ms, only persistent file remains at return. Three simultaneously injected persistent mounts also use one<7s bound rather than3×5s. Released mounts are not retried. |
| T4 replacement | PASS | After initial real EBUSY, fixture overlays target before next pass. Target syscall callback invoked only once. Foreign mount/bytes survive; final verify_identity has no fabricated errno. Overlay then removed by fixture administrator. |
| T5 non-EBUSY | PASS | Injected EIO/EPERM/EINVAL/ENOENT/EACCES each get one attempt, workspace also one; cleanup<1s, saved numeric errno preserved, no retry. |
| T6 primary failure | PASS | Real no-READY service exhausts activation timeout. With transient real FD:7 target attempts/405ms, final TimedOut, empty cleanup errors/residuals. Persistent FD:52 attempts/5001ms, final CleanupFailed, primary TimedOut and original diagnostic preserved. Grace is independent of expired activation deadline. |
| T7 no EBUSY | PASS | One syscall per mount, no sleep, Success/no errors or residuals; full existing notify/input/semantic-proof regressions pass. |
| T8 snapshot/release | PASS | Existing adapter read-only snapshot gets one injected EBUSY per target then succeeds after2 calls; unchanged bytes/service, no readiness claim. Active release succeeds/terminal RolledBack without ERROR after transient EBUSY in three cleanup phases (6 total calls per target). Persistent counterparts retain fail-closed diagnostics. |
| T9 SSH policy integration | PASS | Real production policy→adapter→engine→OpenSSH proofs; controlled synthetic keys only. Injected initial EBUSY per target followed by success (2 calls) commits Applied and emits no ERROR. Permanent injected failure leaves Prepared and its exact ERROR appears in journald. |

No persistent test residual remains after the separate fixture cleanup. Generic
PID1 mountinfo was checked after the final suite: **0 fic-vcsa mounts**. Failed
foreign/persistent cases intentionally retain mounts at product return; only the
controlled fixture subsequently removes them. Current local-only shared cleanup
semantics and downstream retention tests are unchanged.

## Reproduction and evidence

Existing native CMake target automatically includes `CleanupRetryCases.h` via
`VerifiedConfigServiceNativeTests.cpp`; no separate test framework/CI route added.
Build image: `fic-cleanup-diagnostics:debian12`, Debian12/systemd252 with stock
OpenSSH9.2. The full generic suite and SSH suite used separate disposable containers.

Commands executed (paths below are local, ignored build artifacts):

```sh
cmake --build build-startup-classification --target fic verified_config_service_tests ssh_verified_activation_tests -j2
ctest --test-dir build-startup-classification -R '^(verified_config_service_tests|ssh_verified_activation_tests)$' --output-on-failure
# Unprivileged Docker build, repository RO and build output RW, --network none:
cmake -S /src/tests/integration/verified_config_service -B /build -DFIC_TARGET_PLATFORM=debian-12
cmake --build /build --target verified_config_service_native_tests -j2
# In the isolated systemd runtime container:
FIC_ACTIVATOR_NATIVE=1 /usr/local/bin/vcsa-native
FIC_SSH_NATIVE_BUILD_DIR="$PWD/build-cleanup-native" FIC_SSH_NATIVE_SCENARIO=cleanup-diagnostics tests/integration/verified_config_service/openssh_native/run-native.sh fic-cleanup-diagnostics:debian12 debian-12
FIC_SSH_NATIVE_BUILD_DIR="$PWD/build-cleanup-native" FIC_SSH_NATIVE_SCENARIO=release-plan tests/integration/verified_config_service/openssh_native/run-native.sh fic-cleanup-diagnostics:debian12 debian-12
```

Generic runtime used `--privileged --cgroupns=private --network none`, default
private PID/IPC/mount namespaces, only `/run` and `/tmp` tmpfs. **No host binds,
volumes, ports, Docker socket, /etc, /run or host network**. `/sys` was remounted
RO in that container; `/proc/sys` self-bound and remounted RO before systemd.
Docker inspect assertions confirmed namespace/network/bind restrictions. Initial
attempt to remount `/proc/sys` without a bind failed safely before systemd; it
was corrected in disposable preparation, without changing host topology.
SSH runtime uses the existing runner's isolation inspection and disposable-token
namespace/root guards; host SSH file hashes before/after compare equal.

Raw native log, numeric retry summary and inspect receipt:
`build-cleanup-retry-native/evidence/`. SSH7-case JSON, release-plan results,
container inspect and host hashes: `build-cleanup-native/evidence/` and its
parent. Build/unit/native execution logs: `/tmp/fic-cleanup-retry/`.
An initial SSH fixture assertion incorrectly expected2 total calls for an active
release containing several cleanup phases. The corrected hook resets its transient
fault per cleanup and assertions count all phases; final gate passed. No production
proof was relaxed to accommodate the test.

## Security and limits

* Only `umount2(...,0)`; no MNT_DETACH/MNT_FORCE or background cleanup.
* Original namespace/object/mount/source/type checks execute before every retry;
  replacement/disappearance is a terminal error, never adoption or success.
* One5s steady-clock retry budget per Operation cleanup, including workspace;
  RAII cannot start a second budget. No per-mount deadline multiplication.
* Temporary EBUSY is not an ERROR; persistent failure retains primary diagnostic,
  reports one final error per target in reverse order and preserves Prepared rules.
* No MutationJournal, ownership/CAS, success predicate, publication/propagation,
  service units, logging implementation or user configuration changes.
* This does not prove arbitrary holders release within5s, eliminate privileged
  identity-check→umount races, or provide global namespace/recovery guarantees.
* No full cross-distro/project/package matrix or real KESL test run for this patch.
  Owner will separately test the rebuilt FIC with KESL. Old Prepared records are
  not automatically finalized or recovered by this change.
