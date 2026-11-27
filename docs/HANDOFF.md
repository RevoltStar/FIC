# disable_nopasswdlogin completion

## Current base

Branch `main`, base `cf51e64dec72262e6f28bf69e418a6a01ded1b1b`.
The imported `fic-uncommitted.patch` applies on this base.

## Accepted architecture / invariants

One PAM suppression backend for all five platforms. ALT manages gdm-password,
gdm-fingerprint, gdm-smartcard, lightdm, sddm, plasmalogin and emptty;
Debian/Ubuntu manage gdm-password, lightdm and sddm. Default DISABLE and
Recommended dependencies remain. Managed targets do not expand trusted bypasses.

Wrappers bind original bytes, unique adjacent auth anchors and journal mutation
ID. Trusted reads, CAS, durability, fresh graph proof and scoped compensation
preserve foreign changes. Numeric jumps crossing suppression are rejected.
Lost wrappers require installed-package content proof; missing files are never
recreated. Ordinary periodic apply repairs supported package replacement.
NSS and group membership are untouched. No new PAM hooks or package hooks.
Authoritative contract is the PAM suppression section in docs/rollback.md.

## Completed / changed areas

PAM parser/analyzer, fragment, coordinator and package proof; policy and registry;
five profiles; journal validation, rollback and orphan inspection; localization,
unit tests and native fixtures. Real ALT RPM lifecycle passed installation,
CLI apply, periodic repair, refusal of corrupt-witness rollback, and RPM erase
with exact scoped PAM restoration and preserved administrator comment/config.

## Validation

Current run, 2026-11-27, logs in `/tmp/fic-nopasswdlogin-final/`.

- Ubuntu24 profile full configure/build passed, all 3038 build steps.
- 18 static CTests passed (static.log).
- Remaining 218 CTests ran (ctest.log). Eight sandbox socket/process failures
  passed on targeted rerun outside sandbox (socket-retry.log).
- Combined CTest outcome: 219 passed, 17 skipped, zero remaining failures after
  targeted environment retries; two of those skipped root suites additionally
  passed in the disposable container.
- Analyzer, policy, MutationJournal, RollbackExecutor, platform and real
  five-profile registry/dependency/GUI descriptor contracts passed.
- ALT p11 all seven actual RPMs 0.1.1 built (rpm-build.log), artifacts in
  build-nopasswdlogin-package-alt/packages.
- Real systemd RPM lifecycle PASS (lifecycle.log), exported commands/result:
  build-package-lifecycle/native-fic-nopasswdlogin-lifecycle:p11-20261127T141523Z-21113/.
- Original native five-platform PAM, GDM upgrade and ALT control results are
  recorded in the imported patch's HANDOFF. Their referenced logs and binaries
  are absent in this environment; those results were not independently repeated.

## Remaining limits

Root container DM transactions, package PAM hooks and package state store passed
(root-tests.log and root-package-tests.log). Some root/native CTests intentionally
skip under the unprivileged host; their skip is not a runtime PASS.
Graphical login and actual fingerprint/smartcard hardware are outside this gate.
No host PAM changes. Full cross-distribution package lifecycle is not claimed.
