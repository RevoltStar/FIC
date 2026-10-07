# FIC handoff

## Current base

* Branch `main`; starting commit `92f9a61d2fd192c962432e8d60953dccfe01f355`.

## Current task

* Add `NET/SshEdit/ssh_use_pam` and require a proven SSH→PAM bridge before daemon READY when that policy is enabled.

## Accepted architecture / invariants

* `ssh_use_pam` has fixed value `yes`, default `ENABLE`, and uses the existing SSH transaction, mutation journal and ownership-release rollback. Compliant foreign `UsePAM yes` remains unowned.
* OpenSSH effective values come from the trusted `sshd -T` path. The `PAMServiceName` capability is typed per platform. On configurable profiles, the bridge also audits conditional `Match` values through recursive `Include`. On legacy profiles, upstream OpenSSH derives PAM service from `argv[0]`; a read-only systemd unit `ExecStart` proof requires direct trusted `sshd` launch with `argv[0]=sshd`.
* SSH bridge proof follows startup apply and is separate from permanent PAM `pam_fic_access.so` topology proof. Admin policy mutations and periodic apply refresh internal readiness against the live bridge. Disabled `ssh_use_pam` is an explicit opt-out from guaranteed SSH coverage; local PAM infrastructure proof remains mandatory.

## Completed

* Registered the policy, default config, localization, explicit directive semantics and rollback enrollment.
* Added read-only SSH bridge verifier, typed platform routing metadata and startup READY gate.
* Added policy, runtime, platform, rollback, static and readiness decision regressions. Updated SSH and rollback documentation.

## Changed areas

* `fic/src/modules/net/ssh`, `fic/src/incident`, `fic/src/main.cpp`, platform profiles, NET resources, related tests and docs.

## Validation

* Fresh Debian 12 container configure and full build passed. `ctest -N` lists 132 tests. Full root CTest excluding the privilege-sensitive `mutation_journal_tests` passed 131/131 after setting Git `safe.directory=/src` only for that test process; the excluded binary passed separately under UID 1000. Targeted SSH, platform, rollback and static CTest passed 5/5. `git diff --check` passed.

## Remaining

* No code work remains in this focused task.
* Builder images do not contain a runnable `sshd`; real five-distro `sshd -T` and package lifecycle checks have not been run. The ALT p11 builder package index reports OpenSSH `9.6p1-alt7`. The legacy service launch proof covers the declared systemd units; separately launched daemons are outside the proven service contract.
