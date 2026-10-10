# FIC handoff

## Current base

* main; task base 067e887. This snapshot accompanies the FSTAB enrollment commit.

## Current task

* Completed explicit non-reverting rollback enrollment for the 11 OSS/Fstab policies registered in daemon/main_function.cpp.

## Accepted architecture / invariants

* Known FSTAB policies are NotEnrolled: disabling or removing FIC preserves /etc/fstab and current mount parameters.
* Unknown OSS/Fstab policy is Unsupported (fail-closed). No apply/FSTAB implementation or other rollback contracts changed.

## Completed / changed areas

* RollbackExecutor.cpp: exact whitelist of 11 existing policies.
* RollbackExecutorTests.cpp: static/contextual enrollment and disable behavior for all 11 and an unknown future policy.
* docs/rollback.md: explicit lifecycle contract.

## Validation

* Debian12 container: cmake --build /build --target rollback_executor_tests -j2 PASS; ctest --test-dir /build -R '^rollback_executor_tests$' --output-on-failure PASS (1/1).
* Build log: build-prelogin-validation/final/fstab-rollback-build.log.
* git diff --check PASS.

## Remaining

* No remaining task work. No real policy apply, host mount changes or native package removal performed; scope is enrollment and regression checks.
