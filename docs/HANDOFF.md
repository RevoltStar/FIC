# FIC handoff

## Current base

* branch: `main`
* base commit: `2abffc56beaf0ee3acc2f5cadfe4488be1338e4a`

## Current task

Follow-up for `DAC/Mode_and_Owner/mode_and_owner_profiles`: positive
allow-missing capability, Debian-specific `sudoers` presence contract and
full production apply-to-disable regression.

## Accepted architecture / invariants

* One policy maps logical objects to exact metadata profiles. Omitted keys are
  unmanaged; removing a key or disabling the policy never restores metadata.
* `Profile` remains `System`, `Minimum`, `Optimal`, `Strict`.
  `PresenceRequirement` is independent: `MustExist` or `AllowMissing`.
* `_or_not_exists` reuses the base profile metadata and suppresses only absence
  of the primary object. Access failures, broken/unknown symlinks, invalid
  types, provider mismatch and remediation/postcondition failures fail closed.
* Platform `Object.allowMissingVariant` controls public availability. TCB
  credential-file `required` is a separate internal topology contract.
* Source catalogs use the same positive `allowMissingVariant` capability and
  factories propagate it without inversion. Debian 12/13 expose the optional
  `sudoers` variant; Ubuntu 24.04/26.04 and ALT p11 retain mandatory `sudoers`.
* Unconfigured policy uses the generated catalog default. Explicit `{}` is an
  empty managed set, and saved mappings are never auto-filled.

## Completed

* Replaced the source-only negative capability and its inversion with
  `allowMissingVariant = false`; all five production catalogs were converted
  while preserving their prior classifications.
* Debian 12/13 `sudoers` now expose `system_or_not_exists`, so their generated
  defaults tolerate an absent optional sudo package. Explicit `system` still
  requires the file and an existing file is enforced to exact metadata.
* Tests cover positive capability propagation, platform-specific sudoers
  defaults/runtime presence behavior and the real lifecycle
  `apply(strict) -> disable -> strict remains` through `PolicyDisableFlow`.

## Changed areas

* `fic/src/platform/` and all five production profiles
* DAC/platform/rollback tests and architecture documentation

## Validation

* Ubuntu 24.04 affected targets, including `fic`, built successfully in
  `/tmp/fic-followup-build`.
* Targeted required suite passed (8/8), including ModeAndOwner, rollback,
  platform/static, descriptor/registry/CLI and schema tests.
* Debian 12, Debian 13 and Ubuntu 26.04 `mode_and_owner_tests` and
  `platform_profile_tests` built and passed. Ubuntu 24.04 is covered by the
  main tree.
* Full non-root CTest completed: every runnable test passed. Four tests were
  skipped by their environment/root contracts. `session_event_server_tests`
  initially hit sandbox-denied `bind()` and passed when rerun outside sandbox.

## Remaining

* ALT p11 full configure/build is unavailable on this Ubuntu host because its
  PAM transaction module requires ALT PAM development headers. The profile is
  covered by source/static contract checks and a direct syntax check; native
  ALT runtime E2E is deferred.
* Root-only ownership-change plus SUID restoration is conditional and was not
  executed in the non-root CTest run. Ordinary special-bit tests did execute.
* `UserHomes` remains non-production; TCB public allow-missing remains disabled.
