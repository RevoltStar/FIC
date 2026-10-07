# FIC handoff

## Current base

* Branch `main`; starting commit `eb86df6c2c370af571def6b95e847d15a77bc5b7`.

## Current task

* Close three SSH IncidentAccessGate bridge false positives: stale active `sshd`, alternate `-f` relative `Include`, and untrusted future systemd/SSH inputs.

## Accepted architecture / invariants

* `ssh_use_pam` persistent compliance no-op retains no-mutation/no-journal semantics. Runtime reconciliation belongs to access readiness, after the permanent PAM topology proof and before `READY`.
* Read-only bridge proof checks actual and future systemd launches, source authority, `sshd -T`, and actual binary PAM routing. Active services additionally need a successful trusted `systemctl reload` and a fresh bridge/process proof. The conservative implementation reconciles active services on every readiness recomputation.
* Relative OpenSSH `Include` uses the target profile server config directory even with alternate `-f`. Optional missing EnvironmentFiles require a trusted parent; wildcard/expansion forms fail closed. Inactive socket targets and future service inputs are checked.
* `NOT READY` does not stop an already-running unsafe SSH endpoint. Manually launched SSH processes outside declared systemd units remain out of scope.

## Completed

* Added a separate runtime reconciler, trusted input checks via `FileStats`/`TrustedFileReader`, and focused fixture regressions for reload failure/drift, aliases, Include paths, environment precedence, source authority, and inactive socket target.
* Updated the SSH contract in `fic/README.md` and the related static CI check.

## Changed areas

* `fic/src/incident`, SSH runtime/audit, `fic/src/main.cpp`, focused tests, `fic/README.md`.

## Validation

* On an isolated `eb86df6c` snapshot, three RED-before tests failed for stale active runtime, alternate relative Include, and optional wildcard EnvironmentFile.
* Current `ssh_runtime_tests`, SSH static check, and `git diff --check` passed in Debian 12 builder / workspace.
* Disposable Debian 12/13, Ubuntu 24.04/26.04, and ALT p11 OpenSSH `sshd -T -f /tmp/alternate` probes confirmed relative Include resolves under `/etc/ssh` or ALT `/etc/openssh`.
* Fresh Debian 12 configure and full build passed. Root CTest excluding `mutation_journal_tests` passed 131/131; the excluded binary passed separately under UID 1000.

## Remaining

* Create one focused commit and confirm clean working tree.
* Real PID 1 systemd activation/reload and native package lifecycle have not been validated; systemd and process behavior is covered by injected fixtures.
