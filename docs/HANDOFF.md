# fic-prelogin power confirmation follow-up

### Current base

Branch `main`; pre-task base `d60a26c6672263612f23f874ec256fce9a1a7ade`.

### Current task

Align reboot and poweroff confirmations with the light Qt Widgets prelogin view.

### Accepted architecture / invariants

Confirmation is a child overlay of `QtPreLoginView`, with no extra EGLFS window or nested event loop. Broker display updates remain live. Only explicit acceptance sends `R` or `P`; cancellation restores the three main buttons and leaves `pending_` clear. Main handoff shortcuts are disabled during confirmation.

### Completed

Both actions share one centered card and dim backdrop, using existing vector symbols and `AnimatedButton`. The focus starts on Cancel; Enter, Escape, Tab and Shift+Tab are covered by the view tests. Four offscreen Qt Widgets screenshots are in `/tmp/fic-prelogin-confirmation-shots/`.

### Changed areas

`fic-prelogin/src/AnimatedButton.{h,cpp}`, `fic-prelogin/src/QtPreLoginView.{h,cpp}`, `tests/fic/incident/QtPreLoginViewTests.cpp`.

### Validation

`fic-prelogin-frontend` and the affected test targets built in `build-periodic` (Ubuntu 24.04 configuration). `prelogin_qt_view_tests` and `prelogin_package_lifecycle_tests` passed. `prelogin_controller_tests` and `prelogin_frontend_process_tests` passed outside the sandbox; inside it, AF_UNIX bind/send returned EPERM. `git diff --check` passed. Offscreen geometry and screenshots cover 800×600, 1024×768, 1280×720, 1536×1024 and 1920×1080.

### Remaining

Physical EGLFS/KMS rendering and input were not tested. No host power action was performed. No full CTest or native distro matrix was run.
