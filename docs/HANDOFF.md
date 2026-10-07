# FIC handoff

## Current base

* Branch `main`; refactor parent commit `a8524ed6b449ac36b84e4d35de88728a56bfb7af`.

## Current task

* Selectable Incident Response modes and narrow SSH safety gating implemented; continue from this state if runtime or packaging validation is requested.

## Accepted architecture / invariants

* `GLOBAL/lock_settings/incident_response_mode`: DISABLE is OFF; ENABLE/PASSIVE is PASSIVE; ENABLE/ACTIVE is ACTIVE. New defaults are ENABLE/PASSIVE; an unprovable config resolves ACTIVE. Mode and persistent `lockstatus` remain independent.
* OFF makes incident raises inert; PASSIVE persists/audits/notifies without containment; ACTIVE retains fail-closed PAM and existing containment. Only ACTIVE requires `ssh_use_pam` and its PAM/SSH bridge proof.
* The original OpenSSH argv/environment cannot be reconstructed from a running master via `/proc`; only a supported future unit recipe, trusted executable, effective `sshd -T` and PAM topology are proven. Failed ACTIVE SSH proof blocks the declared listener, keeps the administrative daemon available as DEGRADED and never downgrades to PASSIVE. An initial registry failure still prevents normal startup; an ACTIVE startup failure attempts to stop SSH before exit.

## Completed

* Added the authoritative mode resolver shared by daemon, controller and permanent PAM module; conditional Required dependency and API metadata; mode-specific controller behavior and readiness.
* Removed historical systemd activation and runtime reconciliation classes, old execution-environment/argv proof, and their obsolete tests. Kept `SshRuntime` config mutation/journaling and `PamIncidentAccessGateVerifier`.
* Added narrow SSH topology verifier, controlled restart and FIC-owned in-process stop/restore guard; 30-second health check. Added focused regression tests and updated `fic/README.md`.
* Real PID 1 systemd tests of standard SSH service restart, effective UsePAM and unit/socket topology were performed in disposable Debian 12/13, Ubuntu 24.04/26.04 and ALT p11 containers. All temporary containers were removed.
* Debian and ALT packaging order was reviewed: first-install config and lockstatus are established before permanent PAM attachment; no lifecycle change was necessary.

## Changed areas

* `fic/src/incident/`, `fic/src/main.cpp`, mode policy and GLOBAL resources, conditional policy dependency API, platform SSH profiles, relevant tests, `fic/README.md`.

## Validation

* Fresh Debian 12 container configure and full project build succeeded. `ctest -N` found 133 tests; full CTest passed 132/132 excluding `mutation_journal_tests`, which passed separately as UID 1000 (its root-run fault tests cannot model denied filesystem writes). Relevant static and targeted tests passed.
* `git diff --check` passed before this handoff edit. No FIC package installation or actual host PAM/SSH changes were used as validation.

## Remaining

* The emergency SSH guard remembers ownership only within the daemon process. If the process exits after stopping SSH, it will not automatically restore it on restart; local-root recovery is required. Five-distro tests established SSH topology/restart behavior, not FIC package/runtime E2E.
