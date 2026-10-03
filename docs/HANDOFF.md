# FIC handoff

## Current base

* branch: `main`
* base commit: `673b9ea75f4e4b16f301a4dce4aef30a2f6bc1a5`

## Current task

Crash-safe ownership-release apply/rollback for all production
`IDENTITY_ACCESS/USER_CREATION` policies.

## Accepted architecture / invariants

* `/etc/default/useradd`, `/etc/login.defs` and `/etc/adduser.conf` retain all
  foreign bytes; FIC owns only strict per-policy sub-blocks in one logical-EOF
  container.
* Journal payload is typed provenance, never a foreign-value or file snapshot.
  Refresh A to B is one conditional atomic replacement with durable previous
  and target bodies in `Prepared`.
* Rollback releases only an exact owned sub-block. Missing ownership is already
  released; malformed, orphan or edited ownership fails closed.
* `/etc/default/useradd` lookup semantics are profile metadata: legacy-prefix
  on Debian 12/Ubuntu 24.04 and conservatively ALT p11; exact-key on Debian 13
  and Ubuntu 26.04.

## Completed

* Added strict managed-container parsing, consumer-effective last-wins parsing,
  exact in-memory transformations and CAS/durability/compensation transaction.
* Added `MutationBackend::UserCreation`, validated typed payload, explicit
  enrollment/current-route validation and executor dispatch under the shared
  identity configuration mutex.
* Integrated all seven policies, including `GROUPS=` neutralization and atomic
  Debian adduser relation updates.
* Added lifecycle, crash recovery, durability, compensation-race,
  multi-policy, journal, enrollment and executor regression coverage.

## Changed areas

* `fic/src/modules/identity_access/user_creation/`
* `fic/src/platform/`
* `fic/src/rollback/`
* related CMake/tests and rollback/architecture documentation

## Validation

* Ubuntu 24.04: `fic` and affected test targets built; targeted CTest suite
  (platform static checks, `user_creation`, mutation journal, rollback executor,
  platform profile, identity concrete policies, SSH apply/rollback) passed 7/7.
* Debian 12, Debian 13 and Ubuntu 26.04: `user_creation_tests` and
  `platform_profile_tests` passed 2/2 per profile.
* ALT p11 profile source passed direct C++ syntax validation.
* Full E2E/full project CTest intentionally not run per task scope.

## Remaining

* ALT p11 exact-key behavior was not provable from available distro source, so
  its profile deliberately uses the safer legacy-prefix model; supplementary
  groups remain `Unsupported`/`NotEnrolled` there.
* No native package/runtime test was run against real distro useradd/adduser
  binaries; parser/provider behavior is covered by targeted contract tests.
