# disable_nopasswdlogin P1/P2 follow-up

## Current base

Branch main, base 883ff3bcd7024aa073c9f267abf37fb3741656f8.
One local follow-up commit requested; no push.

## Accepted architecture / invariants

Existing five-platform suppression backend, managed service list, raw wrappers,
unique anchors, CAS/durability, package proof and scoped rollback remain.
NSS/group membership is untouched. No new hooks or service-file creation.
Managed service coverage does not expand trusted authentication bypasses.

## Completed / changed areas

P1: RollbackExecutor preserves typed Prepared/releasing intent when suppression
release fails, using the existing SSH/SYSCTL pattern. Only proven terminal
backend release permits success. Retry checks actual fragment/anchors/durability.
No MutationJournal schema change or new fault injection hooks.

P2: Narrow existingServiceOrOther selection is shared by suppression apply and
orphan inspection. Only these callers select root-service Linux-PAM fallback.
The existing parser inspects the selected graph. No writer targets other.

Changed PAM configuration selection, transaction bypass inspection, rollback
executor/orphan inspection, regression/native fixtures and rollback docs.

## Validation

Logs in /tmp/nopasswd-followup/.

- Baseline production RollbackExecutor failed the new typed-intent regression
  with actual post-rename directory fsync failure (p1-baseline-red.log).
- Existing preinstall hook verifies refusal before publication; retry preserves
  concurrent and administrator comments. Post-publication fsync failure retains
  intent; unproven foreign bytes and continued durability failure refuse success.
  Successful retry finalizes ownership and subsequent rollback is idempotent.
- Baseline native ALT Linux-PAM authenticated through other with lightdm absent;
  baseline production driver incorrectly returned ok=1 records=0 (native-red.log).
- Fixed native driver passes absent/safe/bypass/orphan fallback, proves native
  PAM uses other, checks unchanged fallback and no creation (native-green.log).
  Reproduction is tests/integration/pam/nopasswdlogin/fallback-native.sh.
- Four directly affected CTests passed: mutation_journal_tests,
  rollback_executor_tests, pam_control_flow_analyzer_tests,
  pam_disable_nopasswdlogin_policy_tests (ctest.log).
- Final baseline/fixed executor comparison passed (p1-fixed.log). Shell syntax
  and git diff --check passed. No unresolved failure in targeted gates.

## Remaining limits

Native fallback proof is ALT Linux-PAM. Full five-distro matrix, full CTest,
graphical login and package lifecycle were intentionally not repeated for this
local follow-up. Other PAM policies retain their existing service resolution.
