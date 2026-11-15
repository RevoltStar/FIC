# Verified activation cleanup diagnostics — 2026-11-15

Base: `bcf13593ce883123fea183b580703af12f75e4b4`.
Contract: [verified-config-service-activator.md](verified-config-service-activator.md).
This is diagnostic instrumentation, not a fix or causal diagnosis of the reported
shared-cleanup incident. No remaining mounts of the working computer were tested,
unmounted or modified.

## Executed checks

| Requirement | Result and evidence |
| --- | --- |
| T1 real EBUSY | PASS, generic native `cleanupCases`: an actual descriptor holds the published file mount. Ordinary umount returns EBUSY, correct target/stage/numeric errno/text are asserted; primary Success, final CleanupFailed and residual mount retained. Descriptor closes before explicit fixture cleanup. |
| T2 foreign identity | PASS, actual overmount: verify_identity error names the controlled target and has no errno; foreign bytes/mount survive product cleanup. Fixture administrator removes it afterwards. |
| T3 multiple errors | PASS, existing hooks return EBUSY for all umount attempts. At least three errors including both selected controlled targets and workspace are retained; formatted diagnostic includes every error and primary Success. |
| T4 primary + cleanup error | PASS, injected publication EIO plus cleanup EBUSY. Primary MountFailed and its original publication diagnostic are preserved separately from final CleanupFailed. |
| T5 ordinary policy logging | PASS, real initial `ssh_use_pam` apply through production Ssh/adapter/engine with injected cleanup failure. Exactly one captured ERROR contains statuses, target, stage and errno; the complete same ERROR message is present in journald from a transient systemd unit. The journal record is the ordinary Logger stdout output, not a direct journal send. Mutation remains Prepared. |
| T6 success | PASS, generic positive activations retain successful cleanup; focused real policy apply succeeds without cleanup ERROR messages. Unit test verifies unchanged success diagnostic and result fields. |
| T7 snapshot/release | PASS, active verified release fails with detailed diagnostic/provenance retained. Read-only snapshot validation returns CleanupFailed with primary Success, all umount details and no readiness claim; main bytes and service state are unchanged. |

Generic Debian 12 native suite: **208 PASS / 0 SKIP**, including previous shared,
private, namespace, identity, crash/residual and environment tests. Successful
mount/unmount behavior is exercised by the unchanged positive cases. The new
multiple-cleanup-error case only adds a fault-injection assertion.

Focused Debian 12 SSH gate: **4/4 cases PASS** (journal, success, release, snapshot).
Actual packages: OpenSSH `1:9.2p1-2+deb12u10`, systemd `252.39-1~deb12u2`.
Separate release-plan gate: **9/9 PASS**, including existing active/offline/syntax
cases and the new snapshot-cleanup case.

Production `fic` build and local generic/SSH unit builds: PASS, native Ubuntu26
compiler/toolchain with real libraries, no PAM stubs. Final local CTest: **2/2 PASS**
(`verified_config_service_tests`, `ssh_verified_activation_tests`). The SSH suite
also passes in the Debian 12 build container. Initial local SSH unit execution in
sandbox could not enumerate addresses; rerun with read-only netlink access PASS.
Python/shell syntax and `git diff --check`: PASS.

## Actual messages

Real held-descriptor EBUSY (generic native test):

```text
Verified activation failed: primaryStatus=Success status=CleanupFailed; primaryDiagnostic=notify readiness and pinned configuration confirmed within documented observation model; cleanup target=/etc/fic-vcsa-tests/one.conf stage=umount2 reason=ordinary umount errno=16 (Device or resource busy)
```

Actual foreign overmount, logical check (no errno):

```text
cleanup target=/etc/fic-vcsa-tests/one.conf stage=verify_identity reason=cleanup refuses foreign/replaced mount
```

The real policy ERROR recorded in journald includes the following excerpt (the
EBUSY here is injected through the existing test seam, unlike T1):

```text
[ERROR] Применение политики 'ssh_use_pam' не выполнено: ... Verified activation failed: primaryStatus=Success status=CleanupFailed; primaryDiagnostic=notify readiness and pinned configuration confirmed within documented observation model; ... cleanup target=/etc/default/ssh stage=umount2 reason=ordinary umount errno=16 (Device or resource busy); ...
```

Ellipses above are editorial excerpts. The actual single ERROR contains all six
cleanup targets; exact full message is saved in the focused native report and
asserted against journal output.

## Reproduction, isolation and retained artifacts

Use the existing generic native runner and the focused SSH scenario:

```sh
bash tests/integration/verified_config_service/run-native.sh IMAGE debian-12
FIC_SSH_NATIVE_SCENARIO=cleanup-diagnostics \
  bash tests/integration/verified_config_service/openssh_native/run-native.sh IMAGE debian-12
FIC_SSH_NATIVE_SCENARIO=release-plan \
  bash tests/integration/verified_config_service/openssh_native/run-native.sh IMAGE debian-12
```

IMAGE must supply real systemd/OpenSSH/build dependencies and the existing
runtime-init protections. This run used `fic-cleanup-diagnostics:debian12` with a
boot wrapper making sysfs/proc-sys read-only before PID1 and masking coldplug.
Runtime containers have private mount/PID/cgroup contexts, network none, no host
binds, volumes or ports. These properties and read-only mounts were checked.
Build containers alone use read-only repository/build binds and do not run apply.

* `/tmp/fic-cleanup-diagnostics/generic-native.log`: full generic results/messages.
* `/tmp/fic-cleanup-diagnostics/ssh-native-final.log`: focused PASS run.
* `build-cleanup-native/evidence/cleanup-diagnostics.json`: exact policy ERROR,
  captured records, Prepared rows, release and snapshot results.
* `build-cleanup-native/evidence/release-plan-results.json`: release-plan cases.
* `build-cleanup-native/container-inspect.json`: SSH runtime isolation receipt.
* `/tmp/fic-cleanup-diagnostics/generic-container.json`: generic runtime receipt.
* `/tmp/fic-cleanup-diagnostics/local-production-confirm.log`, `final-units.log`,
  `native-build.log`, `release-plan-native.log`: builds/tests.

These ignored/local artifacts describe this working-tree build, not later HEADs.
No compressed evidence archive or new evidence subsystem is introduced. Initial
focused fixtures used an unsupported selection and then attempted re-admission
over intentional residual mounts; both fixture defects were corrected before the
PASS run. Product safety checks were not weakened to make those runs succeed.

## Behavior unchanged / not tested

Code review confirms unchanged reverse cleanup order, namespace/object/mount
identity checks, source/type checks, ordinary `umount2(..., 0)`, residual handling,
result success predicate, propagation policy and MutationJournal lifecycle.
Only stage/errno formatting and SSH diagnostic forwarding change. There is no
retry, adoption, forced/lazy unmount or recovery.

No new full platform matrix, package lifecycle, PAM authentication, real-machine
SSH apply or inspection of the original incident's mounts was performed. The
root cause of that incident remains unknown; the next failure is now observable.
