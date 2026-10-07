# FIC handoff

## Current base

* Branch `main`; follow-up based on `e171cbaac183208ff036a1d2c5730da0fedd6543`.

## Current task

* Close absolute-path/alias PAM detach-proof and recovery config size gaps.

## Accepted architecture / invariants

* `/opt/fic/config` and `GLOBAL.conf` are recovery authority. First install may bootstrap an absent tree; existing unsafe authority is never repaired. Existing config directory and every working `.conf` must have canonical `root:fic` metadata; daemon refuses READY if proof fails.
* Debian removal releases provider and password state before other hooks. The incident gate is detached last. A failed detach restores and proves all five permanent package hooks before `postinst abort-remove` may restart writers; an unproven restoration keeps writers stopped.
* Final gate detach requires a typed, read-only proof across platform PAM directories. `/bin/fic` cleanup follows successful proof.
* The shared maximum working-config size is 1 MiB, including `GLOBAL.conf` recovery reads. The small incident-state reader retains its 4096-byte hard cap.

## Completed

* Detached proof recognizes bare and absolute module names, rejects ambiguous/symlink paths, and recognizes hardlink aliases to the installed gate inode.
* Recovery reader uses the same 1 MiB config limit as schema verification through a parameterized secure-read proof. The short state wrapper remains at 4096 bytes. Repeated parent proofs no longer depend on stale diagnostic text.
* Added boundary/race/repeated-read regressions and a generated Debian `prerm` fixture that calls the production detached-proof implementation on sandbox PAM state.

## Changed areas

* `fic-common/fic-core` secure reader/config size; `fic` incident reader/verifier; related C++ and Debian packaging tests, upgrade contract.

## Validation

* RED-before on `e171cbaa`: both new focused tests failed, one for absolute-path module reference and one for a valid config above 4096 bytes.
* Targeted incident gate, recovery reader, short state and generated Debian packaging tests passed after the fix. Fresh Debian 12 configure/full build passed; `ctest -N` listed 132 tests; root CTest excluding `mutation_journal_tests` passed 131/131, and that test passed separately under UID 1000. The production detached command passed on clean Debian 12 PAM topology in the container. `git diff --check` passed.

## Remaining

* Real package install/upgrade/erase and host PAM mutations have not been run.
