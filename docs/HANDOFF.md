# FIC: передача контекста

## Current base

- Ветка `main`.
- База до текущего commit: `2433ae9`.

## Current task

- Corrective к `836e016`: ограничить FLY `screenlock_timeout` одним
  `ScreenSaverDelay`, не меняя выбранную администратором locker implementation.

## Accepted architecture / invariants

- GNOME и FLY — `MandatoryGlobal`; KDE и XFCE — `SessionOnly`; LXQt —
  `Unsupported`.
- FLY persistent authority —
  `/usr/share/fly-wm/theme.master/themerc`, секция `[Variables]`.
- `screenlock_timeout` управляет только `ScreenSaverDelay=N*60`; выбор locker
  в `ScreenSaver` и `ScreenSaverDBUS` остаётся администраторским состоянием.
- `FlySystemBackend` — единственный persistent FLY enforcement/proof path;
  `FlyBackend` выполняет только session-scoped `fly-wmfunc` runtime calls.
- `DISABLE` не удаляет и не откатывает сохранённые settings.

## Completed

- FLY policy и `FlySystemBackend` управляют и проверяют только
  `themerc/Variables/ScreenSaverDelay=N*60`.
- `ScreenSaver` и `ScreenSaverDBUS` сохраняются как foreign/admin state.
- Session handler выполняет один session-scoped runtime update только для
  `ScreenSaverDelay`; security regression против `current.themerc` сохранён.

## Changed areas

- FLY system/session backends и `OSS_screenlock_timeout`.
- Production desktop backend composition.
- Desktop backend/policy/session/static tests.
- Desktop architecture и session-agent documentation.

## Validation

- Targeted build: `fly_system_backend_tests`,
  `screenlock_timeout_global_tests`, `session_setting_reconciler_tests` —
  passed.
- Targeted CTest: 4/4 passed, включая desktop-environment static security
  check.
- `git diff --check` — passed.
- Полная сборка проекта НЕ запускалась по явному ограничению задачи.

## Remaining

- Нет.
