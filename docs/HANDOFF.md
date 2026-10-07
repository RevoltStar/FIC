# FIC handoff

## Current base

* Branch `main`; follow-up based on `0c2fd02785c63dacb95c5959e21fe4669b1d36f2`.

## Current task

* Close config-authority verification and Debian failed-removal rollback gaps.

## Accepted architecture / invariants

* `/opt/fic/config` and `GLOBAL.conf` are recovery authority. First install may bootstrap an absent tree; existing unsafe authority is never repaired. Existing config directory and every working `.conf` must have canonical `root:fic` metadata; daemon refuses READY if proof fails.
* Debian removal releases provider and password state before other hooks. The incident gate is detached last. A failed detach restores and proves all five permanent package hooks before `postinst abort-remove` may restart writers; an unproven restoration keeps writers stopped.
* Final gate detach requires a typed, read-only proof across platform PAM directories. `/bin/fic` cleanup follows successful proof.

## Completed

* Shared config-authority expectation for schema manager and incident recovery reader; secure metadata proof in `ensureConfigs` and `verifyConfigs`.
* Typed detached proof and maintenance command; full permanent-hook compensation and chained Debian removal recovery fixture.
* Updated schema, incident gate and package lifecycle regressions and package/upgrade documentation.

## Changed areas

* `fic-common/fic-core` config authority/schema; `fic` incident verifier/maintenance; Debian and RPM builders; related tests and docs.

## Validation

* Baseline RED: existing schema test accepted unsafe config directory under old code.
* After the WSL restart, fresh Debian 12 configure and full build passed. `ctest -N` listed 132 tests; root CTest excluding `mutation_journal_tests` passed 131/131, and that test passed separately under UID 1000.
* Targeted schema, incident gate verifier, Debian/ALT packaging and session-agent static tests passed. The production detached-proof command passed against clean Debian 12 PAM topology inside the builder container. `git diff --check` passed.

## Remaining

* Finish final diff/repository audit and commit. Real package install/upgrade/erase and host PAM mutations have not been run.
