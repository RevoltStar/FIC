# FIC handoff

## Current base

* Branch `main`; parent commit `666d01dd755264a6b1af7b754f1196b43d48d654`.

## Current task

* Close SSH IncidentAccessGate false positives from asynchronous reload, unproven systemd lifecycle hooks and unconditional readiness reload.

## Accepted architecture / invariants

* `ssh_use_pam` persistent compliance no-op keeps its existing mutation/journal semantics. Runtime reconciliation is separate from policy apply and follows permanent PAM topology proof before `READY`.
* Effective `Type`, `ExecCondition`, `ExecStartPre`, `ExecStartPost` and `ExecReload` are read from systemd. Unknown pre/post/condition hooks fail closed; trusted `sshd -t` for the same future config and trusted ALT `ssh-keygen -A` are the supported prehooks.
* Signal-based HUP is asynchronous. Active services use `systemctl restart`, require a new `(MainPID, /proc startTime)` generation, then re-prove the complete SSH bridge and socket topology. Only proven `Type=notify-reload` with `CanReload=yes`, empty `ExecReload`, `NotifyAccess=main` and successful `ReloadResult` may use synchronous reload.
* Read-only readiness passes reuse a completed proof only while canonical service identities, process generation, trusted executable and argv, effective lifecycle/launch and trusted config/Include sources remain stable. FIC SSH transaction reload attempts invalidate reuse through an activation epoch, even if config bytes are restored.
* Existing Include base, EnvironmentFile authority, actual PAM routing and fail-closed source checks remain in force. `NOT READY` does not contain an already-running endpoint; independently launched `sshd` is outside this proof.

## Completed

* Implemented typed lifecycle/reconciliation proof and generation-checked restart; added identity-bound read-only readiness and activation epoch.
* Added focused lifecycle, fake reload, HUP, generation, source drift, transaction epoch and no-drift tests; updated SSH static CI check and `fic/README.md`.
* Four RED fixtures against an isolated copy of starting commit failed as expected: fake reload, async HUP, unsafe prehook and no-drift repeat.

## Changed areas

* `fic/src/incident`, SSH runtime/config audit, daemon readiness call, focused tests, `fic/README.md`.

## Validation

* Fresh Debian 12 configure and full build passed; `ctest -N` listed 132 tests.
* Targeted `ssh_runtime_tests`, `daemon_readiness_tests` and SSH static check passed. SSH test binary also passed with a root-owned dummy `/usr/bin/ssh-keygen` bind mount for the ALT lifecycle fixture.
* Full CTest under root first passed 130/132; `path_layout_static_checks` needed `safe.directory=/src` for the read-only bind mount and `mutation_journal_tests` needed non-root UID. With temporary Git trust, 131/131 remaining CTest passed; `mutation_journal_tests` passed separately under UID 1000.
* Four RED fixtures on the exact parent snapshot failed as expected. `git diff --check` passed.
* Package unit files were inspected in disposable Debian 12/13, Ubuntu 24.04/26.04 and ALT p11 containers. PID 1 systemd runtime E2E has not been run.

## Remaining

* Real PID 1 systemd runtime and native package E2E remain untested; unit/package evidence and injected runtime tests support the implementation.
