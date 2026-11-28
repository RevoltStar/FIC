# Prelogin confirmation keyboard tests

### Current base

Branch `main`; pre-task commit `b5f7b86e064a84dc47bac6eb41f3331ef8091b3f`.

### Current task

Stabilize `prelogin_qt_view_tests` after CI failures on Debian 12 and ALT p11 without changing production behavior.

### Accepted architecture / invariants

`QtPreLoginView` owns the confirmation overlay and removes it with `deleteLater()` after cancel or confirm. The test must use Qt keyboard event delivery, retain both `R` and `P` scenarios, and must not dereference the overlay after event processing without a guarded pointer.

### Completed

The held-Return test uses `QPointer` for the overlay, QTest key press/release and QTest's window event path for autorepeat. It checks cancel, no action during held Return, focus transfer to handoff, and exactly one `H` after release and a fresh press. Compound assertions were split. Production code was not changed.

### Changed areas

`tests/fic/incident/QtPreLoginViewTests.cpp`.

### Validation

Debian 12, Qt 6.4.2: original test passed 4/10 and failed 6/10 with `initial Return did not cancel safely`; changed test passed 10/10. ALT p11, Qt 6.11.2: AddressSanitizer on the original test reported heap-use-after-free at `QtPreLoginViewTests.cpp:277`, reading `overlay->isVisible()` after `PowerConfirmationOverlay` destruction; changed test passed 10/10 and one AddressSanitizer run passed. A local Qt 6.10.2 build and 10 test runs passed on an intermediate version. Only targeted builds and tests were run.

### Remaining

At the user's request, Debian 13, Ubuntu 24.04 and Ubuntu 26.04 tests were not run. The Debian 12 failure's individual contributions from the stale overlay pointer and manual key-event delivery were not isolated. The ALT p11 use-after-free is proven by AddressSanitizer; ordinary gdb runs did not reproduce a crash, so there is no gdb crash backtrace. Do not infer production defects from these test failures.
