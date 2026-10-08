# FIC handoff

## Current base

* Branch `main`; HEAD is the P1/P2 hardening commit based on `0afba049237638808e85e2884961531314ad8a74`.

## Current task

* P1/P2 Incident Response SSH hardening: conditional PAM routing, systemd manager environment, guarded ACTIVE transitions and crash-safe SSH block ownership.

## Accepted architecture / invariants

* `OFF` ignores new incidents; `PASSIVE` persists/audits/notifies without active containment; `ACTIVE` additionally contains. Default is `PASSIVE`; untrusted `GLOBAL.conf` resolves `ACTIVE`; `lockstatus` remains independent.
* FIC closes declared SSH entry points before publishing a managed `ACTIVE` transition. Internal `DaemonReadiness::Ready` requires PAM and SSH proof; `sd_notify READY=1` only keeps administrative recovery available.
* SSH proof remains narrow: trusted future unit recipe, effective `UsePAM` and conditional `PAMServiceName`, PAM topology, trusted executable and allowlisted manager environment. It does not reconstruct historical argv/environment from `/proc`.
* `/run/fic/incident-ssh-block` is boot-scoped ownership only. `intent` precedes stop; `stopped` follows confirmed inactive. Ambiguous or untrusted ownership never authorizes automatic start.

## Completed

* Added conditional `PAMServiceName` verification through `SshRuntime::verifyPolicyValue()` and fail-closed `systemctl --system show-environment` proof before and after SSH activation.
* Guarded managed mode mutations before config writes and ACTIVE startup before policy application; retained administrative IPC on degraded prerequisite.
* Persisted SSH stop ownership with secure atomic witness, boot ID, exact declared unit names and intent/completed states. Initial service/socket states are captured together because `stop ssh.socket` can also stop `ssh.service`; failed/deactivating units do not become owned.
* Added focused regression tests and updated `fic/README.md`.

## Changed areas

* `fic/src/incident/`, `fic/src/main.cpp`, `tests/fic/incident/`, `tests/fic/modules/net/ssh/`, `tests/CMakeLists.txt`, `fic/README.md`.

## Validation

* Base HEAD confirmed; P1-A, P1-B, P1-D and P2 regressions failed before implementation on base. The P1-C production IPC transition was not safely reproducible against host SSH; source ordering on base showed config mutation before prerequisite recomputation.
* Targeted Debian 12 container build of `fic`, `ssh_runtime_tests`, `incident_response_mode_tests`, `incident_mode_transition_tests` succeeded. Targeted CTest passed 4/4; `mutation_journal_tests` passed separately as UID 1000.
* Real PID 1 disposable Debian 12/13, Ubuntu 24.04/26.04 and ALT p11 containers: `systemctl --system show-environment` and `sshd -T` observed; stock variables are `LANG=C.UTF-8` and canonical `PATH`, `UsePAM=yes` on all. Modern Debian 13/Ubuntu 26.04 expose `pamservicename sshd`; other profiles use the legacy route. Debian 13 conditional `PAMServiceName custom` resolved for `alice`; Ubuntu 24.04 restored `ssh.socket` before `ssh.service`, both active.
* Fresh Debian 12 container configure and full build succeeded. Final incremental full build and CTest passed 133/133, excluding only `mutation_journal_tests` run separately under UID 1000.

## Remaining

* Full FIC package/runtime mode transition and crash/restart E2E were not exercised in the five systemd containers. Injected unit tests cover ownership state machine; real-container evidence covers stock systemd environment and SSH configuration.
* Manager environment snapshots cannot distinguish a privileged change followed by a return to the original value between reads. Externally writing `GLOBAL.conf` outside daemon IPC cannot be synchronized with its moment of publication.
