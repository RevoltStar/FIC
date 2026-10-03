# FIC handoff

## Current base

* branch: `main`
* base commit: `b062092a4118eaf68b67c6a48fa6b4ee9e3b65d8`

## Current task

Follow-up fixes for crash-safe ownership and native-consumer semantics of all
production `IDENTITY_ACCESS/USER_CREATION` policies.

## Accepted architecture / invariants

* Strict FIC managed-block grammar and native consumer-effective parsing are
  separate; only exact journal-bound managed bodies prove ownership.
* Foreign configuration remains byte-for-byte outside per-policy blocks; the
  journal contains typed FIC provenance, never foreign snapshots.
* Refresh `A -> B` remains one physical CAS replacement. If rollback proves
  physical `A` while the journal is `Prepared(A -> B)`, the same record is
  durably normalized to `Prepared(target=A)` before any physical release.
* Ordinary apply cannot replace unresolved `Prepared` or `RollbackFailed`
  USER_CREATION provenance.
* All supported `/etc/default/useradd` packages are modeled exact-key and
  last-wins. Empty shadow `GROUPS=` is ignored after a non-empty assignment;
  it is not a neutralizer.

## Completed

* Added consumer-effective parsing for shadow `login.defs`, adduser.conf and
  useradd defaults without weakening managed-block ownership parsing.
* Corrected all five profiles to package-proven exact-key useradd semantics,
  including ALT p11 shadow-utils 4.17.4-alt2.
* Empty shadow supplementary groups now release an owned block only when the
  remaining foreign state is already empty; otherwise apply fails closed.
* Added durable previous-side normalization, USER_CREATION journal transition
  guards and executor-level retry/crash/third-state regression tests.
* Native disposable probes covered actual shadow/adduser behavior on Debian
  12/13, Ubuntu 24.04/26.04 and ALT p11 without changing the host.

## Changed areas

* `fic/src/modules/identity_access/user_creation/`
* `fic/src/platform/`
* `fic/src/rollback/`
* related USER_CREATION/platform/journal/executor tests and rollback docs

## Validation

* Ubuntu 24.04: affected targets including `fic` built; targeted suite passed
  7/7 (`user_creation`, journal, executor, platform/static, identity and SSH).
* Debian 12, Debian 13 and Ubuntu 26.04: `user_creation_tests` and
  `platform_profile_tests` built and passed 2/2 per profile.
* ALT p11: native builder configured successfully; both affected targets built
  and their executables passed (the image has no `ctest` command).
* Native package probes used real user creation in disposable containers to
  validate login.defs and adduser.conf, plus `useradd -D` for defaults.

## Remaining

* Full project CTest and E2E were intentionally not run per task scope.
* No host policy/configuration files were modified by runtime probes.
