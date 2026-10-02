# FIC handoff

## Current base

* branch: `main`
* base commit: `e11aaec0a0dc79c3cb9a5b78ee8100ea4f76dc99`

## Current task

Follow-up for `DAC/Mode_and_Owner/mode_and_owner_profiles`: explicit
`Profile` + `PresenceRequirement`, generated fresh-install default and
release-only production disable flow.

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
* Unconfigured policy uses the generated catalog default. Explicit `{}` is an
  empty managed set, and saved mappings are never auto-filled.

## Completed

* Parser, canonical JSON, restriction info and execution plan carry separate
  profile/presence values; the old StaticPath `PathContract.required` source
  was removed.
* Generated defaults select `system_or_not_exists` only for platform-declared
  allow-missing objects. `arp` has that capability on all five profiles; its
  utility package is not a FIC dependency.
* Fresh `DAC.conf` omits `.value`; policy-specific apply uses its generated
  default only while unconfigured.
* Broken allowed/provider symlinks are no longer collapsed into successful
  ENOENT. Existing targets retain exact owner/group/mode enforcement.
* The daemon disable sequence is in `PolicyDisableFlow` and is used by the
  actual `disable_policy` path. Its DAC regression proves persisted DISABLE,
  unchanged metadata/value and no rollback journal.
* Tests cover parser variants, ENOENT versus EACCES/unsafe topology, defaults,
  fresh bootstrap, exact remediation, chown plus SUID restoration and runtime
  failure aggregation.

## Changed areas

* `fic/src/modules/dac/mode_and_owner/`
* `fic/src/platform/` and all five production profiles
* `fic-common/fic-core/src/fs/FileStats.cpp`
* daemon disable flow and DAC default config
* DAC/platform/schema/rollback tests and architecture documentation

## Validation

* Ubuntu 24.04 full build succeeded in `/tmp/fic-followup-build`.
* Full non-root CTest passed: 115 executed/passed, one root-labelled test
  (`command_hash_batch_tests`) skipped by contract.
* Targeted required suite passed (8/8), including ModeAndOwner, rollback,
  platform/static, descriptor/registry/CLI and schema bootstrap tests.
* Debian 12, Debian 13 and Ubuntu 26.04 `platform_profile_tests` built and
  passed. Ubuntu 24.04 is covered by the main tree.

## Remaining

* ALT p11 full configure/build is unavailable on this Ubuntu host because its
  PAM transaction module requires ALT PAM development headers. The profile is
  covered by source/static contract checks; native ALT runtime E2E is deferred.
* Root-only ownership-change plus SUID restoration is conditional and was not
  executed in the non-root CTest run. Ordinary special-bit tests did execute.
* `UserHomes` remains non-production; TCB public allow-missing remains disabled.
