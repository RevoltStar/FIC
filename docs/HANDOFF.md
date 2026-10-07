# FIC handoff

## Current base

* Branch `main`; starting commit `bfda1f47581effad20d3018e5532ea0c84ca73c6`.

## Current task

* Harden `ssh_use_pam` bridge and daemon READY against distro capability drift, actual systemd launch overrides and PAM topology drift.

## Accepted architecture / invariants

* `ssh_use_pam` managed configuration, journal and rollback are unchanged. Its opt-out skips only SSH proof; permanent PAM topology proof is always required.
* The trusted runtime `sshd` selects modern `PAMServiceName` or legacy argv-name routing. Platform routing metadata is only a package baseline.
* SSH proof covers declared systemd service/socket units. Active services use trusted `/proc/<MainPID>/exe` and argv; inactive services use effective systemd launch properties and strictly parsed environment files. Test mode reuses proven `-f` and `-o` arguments. Unknown launch semantics fail closed.
* READY is recomputed from both PAM topology and the optional SSH bridge at startup, after relevant admin commands and after periodic apply. No host SSH state is changed by the proof.

## Completed

* Added runtime capability probe, typed systemd/process activation verifier, composite access readiness, and focused regressions for backports, launch overrides, sockets, process drift and PAM drift.
* Updated the SSH contract in `fic/README.md` and the related static CI check.

## Changed areas

* `fic/src/incident`, `fic/src/main.cpp`, SSH runtime, platform SSH metadata, focused tests and SSH documentation.

## Validation

* RED before the fix: Debian 12 baseline plus modern `PAMServiceName custom`, active launch `-o UsePAM=no`, and alternate `-f` regressions failed on `bfda1f4`.
* Fresh Debian 12 container configure and full build passed; `ctest -N` listed 132 tests. Full root CTest excluding `mutation_journal_tests` passed 131/131 with Git safe-directory scoped to the test process. The excluded binary passed separately under UID 1000.
* Disposable Debian 12/13, Ubuntu 24.04/26.04 and ALT p11 containers ran real `sshd -T`; their installed SSH units were inspected. No systemd PID 1 end-to-end activation test was run.

## Remaining

* Live systemd/PID 1 activation end-to-end and native package lifecycle were not validated. The systemd property and `/proc` scenarios are covered by injected test fixtures. Separately started `sshd` processes outside declared units remain out of scope.
