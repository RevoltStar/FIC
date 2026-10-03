# FIC handoff

## Current base

* branch: `main`
* base commit: `a1c13198c1dd4872c34c0095a35f98d94bc4ea7c`

## Current task

Evidence-driven correction of `/etc/default/useradd` native semantics and
`user_default_supplementary_groups` empty-list enforcement.

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
  last-wins. Shadow 4.17 `GROUPS=` clears the actual `user_groups` membership
  state even when `useradd -D` displays stale `def_groups`.

## Completed

* Added consumer-effective parsing for shadow `login.defs`, adduser.conf and
  useradd defaults without weakening managed-block ownership parsing.
* Corrected all five profiles to package-proven exact-key useradd semantics,
  including ALT p11 shadow-utils 4.17.4-alt2.
* Empty shadow supplementary groups use a normal FIC-owned EOF `GROUPS=`
  assignment; non-empty-to-empty and reverse transitions use the generic
  atomic refresh state machine without a release window.
* Added durable previous-side normalization, USER_CREATION journal transition
  guards and executor-level retry/crash/third-state regression tests.
* Exact-key semantics were reconciled with distro sources: shadow 4.13's
  prefix macro compares complete tokens such as `HOME=`, not bare `HOME`.
* Real-user probes on Debian 13 and Ubuntu 26.04 proved that `GROUPS=a,b`
  followed by `GROUPS=` creates a user with no supplementary memberships.

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
* Detailed current research evidence is in
  `/tmp/user_creation_native_semantics.md` (not committed).

## Remaining

* Full project CTest and E2E were intentionally not run per task scope.
* No host policy/configuration files were modified by runtime probes.
