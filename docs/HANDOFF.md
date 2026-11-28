# fic-prelogin confirmation keyboard follow-up

### Current base

Branch `main`; pre-task base `d445af99d4cdb127fc3533ac0172ea9945b0ce6f`.

### Current task

Prevent Enter autorepeat from handing off after confirmation cancellation and keep Tab traversal inside the open power confirmation.

### Accepted architecture / invariants

The child QWidget overlay and its visual design are retained. Only explicit confirmation sends `R` or `P`. Cancellation restores the main controls; a fresh Return still triggers one `H`. IPC display updates remain live while the overlay is open.

### Completed

`QtPreLoginView` disables autorepeat on the handoff and confirmation Enter shortcuts. A local event filter on the two confirmation buttons loops Tab and Shift+Tab between them; the overlay itself is not focusable. Regression tests use `QKeyEvent(isAutoRepeat=true)` and multiple real focus cycles for both actions. The tests failed on the previous code for both focus escape and held Return, then passed after the respective fixes.

### Changed areas

`fic-prelogin/src/QtPreLoginView.cpp`, `tests/fic/incident/QtPreLoginViewTests.cpp`.

### Validation

`fic-prelogin-frontend` and `prelogin_qt_view_tests` built in `build-periodic`. `prelogin_qt_view_tests` and `prelogin_package_lifecycle_tests` passed in the sandbox. `prelogin_controller_tests` and `prelogin_frontend_process_tests` passed outside it because the sandbox denies AF_UNIX bind/send with EPERM. `git diff --check` passed.

### Remaining

Physical EGLFS/KMS keyboard input was not tested. No full CTest or native distro matrix was run. No host power action was performed.
