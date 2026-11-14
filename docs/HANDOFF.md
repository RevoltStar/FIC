# Current workspace

## Current base / task
* main; HEAD — `fix(device): decouple service readiness from startup reconciliation` (commit 1) + uncommitted test follow-up (commit 2 of the same task).
* Fixed: `fic-device.service` is now `Type=notify` (`NotifyAccess=main`, `TimeoutStartSec=600s`); `fic-dick --daemon` sends `sd_notify("READY=1")` after devices.db init, `regenerate_device_policy()` (compile+activate+connected-denial enforcement) and both IPC sockets, strictly BEFORE `run_device_reconciliation("daemon startup")`. `fic-dick wait-daemon 30` removed from `fic.postinst` and `fic.post` (the `systemctl start` job now waits for READY; `fic --maintenance wait-daemon 30` for the main daemon retained; the `wait-daemon` MODE remains for `fic-udevadm-trigger` and others).

## Readiness contract (authoritative)
* Service ready = devices.db initialized + device policy activated + both sockets exist. READY=1 proves exactly this.
* NOT guaranteed at install time: administrative IPC responsiveness during the synchronous startup reconciliation, reconciliation completion, reconciliation success. Reconciliation keeps its synchronous model and the existing retry path (`DeviceEventQueue`, bounded 5 s backoff); failures are logged and retried, never masked by READY.
* `fic-dick` links `PkgConfig::FIC_DICK_LIBSYSTEMD` (same pattern as `fic`); DEB Depends gains `libsystemd0` automatically via `detect_binary_depends`/dpkg-shlibdeps; RPM auto find-requires covers libsystemd.so.0.
* Native probe `slow_init_negative` discipline: corrupted devices.db → `systemctl start` must exit NON-ZERO (start job fails: no false READY) AND the service must not be active; both facts are recorded in the `negative-readiness` timeline entry, and the original DB/service state is restored BEFORE any early verdict.
* Native probe `slow_init_native.py`: verdict `PASS-FIXED` (exit 0) = reinstall succeeded (dpkg exit 0) while the 45 s injected reconciliation was still running, injection started strictly after socket bind (CLOCK_REALTIME ns vs socket `st_mtime_ns`, no tolerance), same `MainPID` answers IPC after the delay, `dpkg --configure -a` OK, retained config/journal intact. Negative readiness check: corrupted devices.db → start job FAILED with exit 1 (no false READY). `INCONCLUSIVE` exits non-zero and keeps its specific reason (main catches `Exception`, not `BaseException`).
* Latest native run (Debian 12, real DEBs, fixed binaries): reinstall 3.1 s (was: exit 1 after ~33 s), PID 1040 → 1040, sleep 44.997/45 s, negative start exit 1 / state failed, full timeline incl. recovery; full `deb_native.py` gate: PASS. Evidence in `build-package-lifecycle/native-…` (not committed).
* Minimal fix proposal was implemented via Type=notify (the previous proposal of a readiness thread is obsolete).

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
