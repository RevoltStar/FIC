# Current working state

## Current base
* Branch main; base `aecd4a905deec5c47c5c96e7955d0775d128de35`. Initially clean; completion commit follows this base. No push.

## Current task
* Remove implicit ownership fallback from SharedLoginDefsPolicySpec without changing policy behavior.

## Accepted architecture / invariants
* All seven enrolled USER_CREATION/PASSWORD_AGING policies explicitly retain OwnWhileEnabled.
* A required six-argument constructor prevents omitted ownership from being silently value-initialized by aggregate initialization. No default construction or five-argument spec.
* Repository-wide dependencies checked: obsolete enum value was used only by its member default and an unreachable backend branch. Journal consumers read policy/key/domain metadata; ownership is not serialized.
* Apply/rollback, CAS, journal/recovery, relation guards and USER_CREATION behavior remain unchanged; unknown policies still fail closed through existing route/whitelist validation.

## Completed / changed areas
* IdentityLoginDefsPolicySpec.h: removed default and unused enum alternative; mandatory explicit constructor argument.
* IdentityLoginDefsManagedTransaction.cpp: removed unreachable foreign-compliance no-op branch.
* IdentityLoginDefsTests.cpp: compile-time construction guards, all-seven ownership assertions and unknown-policy fallback rejection. Existing ownership/release/recovery lifecycle tests retained; included in normal CI target.

## Validation
* Docker Debian12 build PASS: fic, identity_login_defs_tests, user_creation_tests, password_aging_tests, mutation_journal_tests, rollback_executor_tests. Log /tmp/fic-explicit-ownership-validation.log.
* Final related CTest5/5 PASS with DAC_OVERRIDE/DAC_READ_SEARCH dropped: /tmp/fic-explicit-ownership-final-ctest.log. Initial root-capable run bypassed read-only directory fault injection in mutation_journal_tests; corrected container capabilities, no production workaround.
* git diff --check PASS; repository-wide git grep found no remaining obsolete enum references. Compile-time guards compiled successfully; existing shared ownership/release/recovery and USER_CREATION regressions PASS.

## Remaining / limits
* No unfinished implementation. One completion commit, no push.
* Previous five-platform native matrix not repeated: this task enforces compile-time metadata construction and removes unreachable code. No host security mutations.
* Existing unrelated ALT platform_profile_tests SDDM-path mismatch remains outside scope (see password-aging-native-validation.md).
