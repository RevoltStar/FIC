# Current workspace

## Current base / task
* main; HEAD — follow-up `fix(prelogin): refine light UI layout and geometry checks` on top of `19b2c8e5`.
* Visual refinement of the light prelogin UI (Model A session work remains committed earlier).

## Accepted architecture / invariants
* `fic-prelogin` frontend remains Qt6 Widgets + EGLFS/KMS; no QML/WebEngine/OpenGL widgets.
* `PreLoginController`, broker IPC protocol, peer-credential checks, DRM seat selection and Qt platform initialization are UNCHANGED; redesign is view-only (`QtPreLoginView`, `AnimatedButton`, new `PreLoginStepsWidget`).
* Three visual init steps (демон FIC / первичное применение политик / передача DM) map onto existing controller states only: WAITING_FOR_DAEMON→(W,W,W), DAEMON_STARTING→(A,W,W), STARTUP_APPLYING→(D,A,W), STARTUP_SUCCEEDED→(D,D,W), STARTUP_FAILED→(D,F,W)+error banner, DAEMON_DEGRADED→(W,!,W)+warning banner (no green checks), DAEMON_UNAVAILABLE→(F,W,W)+error banner, HANDOFF→(D,D,A), POWER_ACTION→(W,W,W)+info banner. Step indicators are visual sequence, not security attestation.
* IPC payload schema unchanged: exactly 5 string fields ≤4096 chars; all diagnostic text rendered with Qt::PlainText; diagnostics live in a bounded QScrollArea so buttons never leave the screen.
* Background is a cached QPixmap rebuilt only on resize (no continuous full-screen repaints); spinner is a 70 ms QTimer repainting only the steps widget and stops when no step is Active.
* Button actions ('H'/'R'/'P'), `pending_` idempotence, QMessageBox confirmations, Alt+D/Enter shortcuts preserved.

## Completed / changed areas
* `fic-prelogin/src/PreLoginStepsWidget.{h,cpp}` — new widget: 3 steps with Waiting/Active/Done/Failed/Warning indicators, per-step active captions.
* `fic-prelogin/src/QtPreLoginView.{h,cpp}` — light wavy background, white card with shadow, vector FIC shield, permanent title «Инициализация системы безопасности», state as first diagnostics line, state-colored banner, steps, diagnostics scroll, handoff/reboot/poweroff buttons with vector icons (Monitor/Restart/Power). Follow-up: adaptive card size in resizeEvent (~82% width on the 1536×1024 reference, min 744, cap 1400; height cap 780), shadow drawn OUTSIDE the card bounds (softer, denser near the panel, offset down), steps left-aligned, diagnostics compact (stretch at bottom, gap between steps and buttons).
* `fic-prelogin/src/AnimatedButton.{h,cpp}` — light theme colors, sizeHint/minimumSizeHint accounting for icon (prevents text clipping), symbol drawing takes the state-matched color from paintEvent (disabled icon follows gray disabled text); animation (160 ms OutCubic) and focus/disabled/pressed states preserved.
* `fic-prelogin/CMakeLists.txt` — PreLoginStepsWidget added to `fic-prelogin-view` + moc list.
* `tests/fic/incident/QtPreLoginViewTests.cpp` — step-matrix for all 9 states, banner assertions (no false success on DEGRADED/POWER_ACTION), button geometry checks via `mapTo(&view, …)` in view coordinates (positive size, visible, inside the view AND inside the card, no pairwise overlap) at 800×600/1024×768/1280×720/1536×1024/1920×1080, panel ratio check ~110–140% on ≥1536, disabled-icon pixel check (darkest icon pixel lightens when disabled), degraded-no-green-checks; optional PNG snapshots of real widgets via env `FIC_PRELOGIN_SHOTS=<dir>`.

## Validation
* Full build OK on base (`cmake --build build-check -j4`, 100%, 0 errors); full CTest on base 226/229; the 3 failures (`incident_state_lifecycle_static_checks`, `identity_policy_hierarchy_tests`, `display_manager_transaction_tests` "root unit") reproduce on clean base `9cccedf5` (verified via stash) and are unrelated to prelogin work.
* Follow-up: targeted build of `fic-prelogin-view`, `fic-prelogin-frontend`, `prelogin_qt_view_tests` OK; `prelogin_qt_view_tests`, `prelogin_controller_tests`, `prelogin_frontend_process_tests`, `prelogin_package_lifecycle_tests` PASS; `git diff --check` clean.
* Sandbox lacks PAM dev headers and libpam; configure/build used temporary stub headers + stub libpam.so in `/tmp/fic-pam-stub` (NOT in the repository, passed via CMAKE_INCLUDE_PATH/CMAKE_LIBRARY_PATH). When real PAM dev headers appear, rebuild without stubs.
* Screenshots (real widgets, offscreen): `/tmp/prelogin-shots/*.png` (9 states + resolution_800x600/1280x720/1536x1024/1920x1080).

## Remaining / limits
* Real EGLFS/KMS hardware run not possible in this sandbox; offscreen results do not prove real KMS behavior.
* Spinner animation speed/visual on real EGLFS not measured.
* Pre-existing unrelated failures listed above (identity hierarchy PAM preflight, DM root container, RPM manifest static check) need separate investigation.
* Cross-distro builds (debian-12/13, ubuntu-24.04 target, alt-p11) for the new UI not run beyond ubuntu-24.04 configure used here.
