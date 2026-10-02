# FIC handoff

## Current base

* branch: `main`
* base commit: `2839b6a56020564357d9f438c20350809533dc30`

## Current task

Follow-up hardening of `DAC/Mode_and_Owner/mode_and_owner_profiles`: exact
profile state, logical generated default, per-object missing semantics and
restored security regression coverage.

## Accepted architecture / invariants

* The policy value is `object=profile` in TextEdit and canonical JSON in
  storage; only explicitly selected objects are managed.
* Omitted/removed objects and policy DISABLE release management without any
  chmod/chown or rollback. Explicit `object=system` applies the verified
  distribution system contract.
* Platform catalogs use typed StaticPath, PathCollection, UserHomes and
  TcbCredentialTree targets. Every exposed object has `system`; other profiles
  are optional and are not treated as an ordered scale.
* Provider-managed resolv targets are allowlisted and validate-only. TCB keeps
  descriptor-relative nofollow/topology proofs. UserHomes is account-aware and
  never recursively changes the home root.
* Every profile is an exact owner/group/mode desired state. Required/optional
  is declared per platform path contract.
* The logical default selects every current object as `system`; an existing
  saved explicit mapping is never auto-filled, so an omitted key remains
  unmanaged after upgrades.

## Completed

* One production Mode_and_Owner policy is registered; old three policies and
  DAC platform-baseline rollback/journal action were removed.
* Debian 12/13, Ubuntu 24.04/26.04 and ALT p11 expose one logical-object
  catalog. Commands (`df`, `chattr`, `arp`, `ip`) are independent objects;
  no duplicate `verified*` fields remain in `DacPlatformConfig`.
* Parser/canonical storage, complete preflight, aggregate execution,
  per-object type/missing/mode/remediation semantics and postcondition reuse
  are implemented.
* Config, localization, architecture/rollback docs and targeted tests were
  updated.
* Follow-up removed `MaximumAllowed` and the global missing-file policy from
  this subsystem. A failed ownership change now stops mode mutation for that
  object, avoiding a partially applied profile.
* Production catalogs mark `fstab`, `group`, `passwd`, `shadow`, `sudoers` and
  `df`/`chattr`/`arp`/`ip` required on every supported platform;
  `hosts_allow`, `hosts_deny` and `securetty` remain explicitly optional.
* Tests cover exact bidirectional transitions, SUID/SGID/sticky, required and
  optional missing objects, invalid identities and non-root chown failure,
  partial release, provider type/metadata safety, stored-value preflight and
  the logical default emitted through `PolicyRegistryJson`.

## Changed areas

* `fic/src/modules/dac/mode_and_owner/`
* `fic/src/platform/`, all production platform profiles
* daemon registration, DAC default config/localization
* rollback journal/executor DAC cleanup
* DAC, rollback, platform and CLI/static tests

## Validation

* Ubuntu 24.04 full build succeeded in `/tmp/fic-followup-build`.
* Targeted CTest passed (7/7): `mode_and_owner_tests`,
  `rollback_executor_tests`, `platform_profile_tests`,
  `platform_profile_static_checks`, `cli_policy_set_tests`,
  `module_registry_tests`, `policy_descriptor_tests`.
* Full non-root CTest: 115 passed or conditionally skipped; only
  `session_event_server_tests` failed inside the sandbox because `bind()` was
  denied. Its isolated rerun outside the sandbox passed (1/1).
* Debian 12, Debian 13 and Ubuntu 26.04 `platform_profile_tests` build and
  pass after the single-catalog refactor. ALT p11 profile sources pass a
  direct C++ syntax check; full ALT
  configure is unavailable on this Ubuntu host because PAM development
  headers required by `pam_fic_pwtxn` are absent.

## Remaining

* `home` and production `user_homes` objects are intentionally not exposed:
  the repository contains no verified per-platform system metadata contract
  for user home directories. The typed UserHomes handler is implemented and
  covered with a synthetic contract.
* Full distribution/runtime E2E and privileged real-filesystem apply were not
  run; the task intentionally uses unit/integration/static validation only.
