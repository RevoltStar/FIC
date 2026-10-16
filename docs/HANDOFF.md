# Current working state

## Current base
* Branch main; base `87af7c601837c20b060999e7ca464e3de25f3c68`. Initially clean; completion commit follows this base. No push.

## Current task
* PASSWORD_AGING ownership/non-reverting lifecycle complete. One completion commit. User explicitly authorized Docker instead of unavailable Podman.

## Accepted architecture / invariants
* All five scalar specs explicitly OwnWhileEnabled; shared USER_CREATION EOF container, MutationJournal/CAS/recovery and per-element release unchanged. Fresh matching foreign value requires own block/journal. No snapshots/foreign adoption/group rollback/migrations. USER_CREATION specs unchanged.
* Operational code/dependencies unchanged: each apply rereads effective config/accounts, skips compliant users, verified chage + sp_lstchg invariant; first error Failed, next apply rechecks everyone. All local UID0 names for root policy. NotEnrolled/no per-user journal.
* Native missing PASS_MIN_DAYS/PASS_MAX_DAYS/PASS_WARN_AGE = -1 on all five installed versions. Profiles unchanged. ALT real TCB; no host account/security mutations.

## Completed / changed areas
* Production: only IdentityLoginDefsPolicySpec.h, five explicit ownership requirements.
* Existing identity_login_defs_tests expanded across all five policies: fresh matching/differing, durable ownership, repeat, refresh, append, shared peers, release, edits/orphans. Existing CAS/relation/journal/recovery guards retained. password_aging_tests adds same-instance retry after middle failure, external drift and changed expected settings.
* tests/integration/password_aging: focused production driver, native gate/runner, ALT runtime recipe with shadow-change. Reuses USER_CREATION CMake platform/core setup. Actual useradd/chage and shadow/TCB, process cuts, UID0 aliases; source mounts read-only.
* docs/rollback.md, architecture-diagrams.md and password-aging-native-validation.md document contracts, versions, commands, seven-policy matrix and limits.

## Validation
* Five Docker native rows PASS:133 checks each,665 total,50 real process cuts,0 SKIP. /tmp/fic-aging-native-<row>-final.log; rows debian12/debian13/ubuntu2404/ubuntu2604/alt-p11. Native retry injects only command2 failure; other chage calls real. Installed versions and source cross-check (shadow4.13/4.17.4) recorded in native report.
* Debian12 full configure/build PASS; full CTest184/185. Sole failure was Git safe.directory in path_layout_static_checks; corrected container env and final shared test rerun2/2 PASS (/tmp/fic-aging-debian12-final-rerun.log). Other184 full tests passed (/tmp/fic-aging-debian12-full.log).
* Other4 platforms: fic builds PASS; final related password_aging/user_creation/identity_login_defs CTests3/3 each PASS (/tmp/fic-aging-focused-<row>-final.log). Additional platform_profile_tests PASS on Debian13/Ubuntu24/Ubuntu26.
* Host tracked-path static check after staging new files PASS; bash syntax/Python AST and git diff --check PASS. Existing CTest targets include new cases in normal CI.

## Remaining / known limits
* No unfinished PASSWORD_AGING work. Existing unrelated ALT platform_profile_tests fails SDDM path: test expects /etc/sddm.conf, unchanged profile specifies /etc/X11/sddm/sddm.conf. Both inputs identical to base; not changed here. ALT native profile/missing-key assertions PASS.
* Process cuts are not physical power loss. No real-machine PAM/login tests or universal useradd/adduser UID scope guarantee. Existing CAS retains its documented boundary against arbitrary external writers.
* Builders/cache names and reproduction commands in native report/run-native.sh; ALT runtime fic-aging-native:alt-p11 has shadow-utils/shadow-change4.17.4-alt4. Initial missing-chage, logger-glob and journal-witness fixture issues were corrected before final gates; old non-final logs contain those harness failures.
