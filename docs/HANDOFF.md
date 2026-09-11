# FIC: передача контекста

## Current base

- Ветка `main`.
- База до текущего commit: `7fe411d`.

## Current task

- Устранить false success XFCE `screenlock_timeout`, сохранив XFCE в
  `SessionOnly`.

## Accepted architecture / invariants

- GNOME и FLY — `MandatoryGlobal`; KDE и XFCE — `SessionOnly`; LXQt —
  `Unsupported`.
- Xfconf Kiosk Mode не является security-authoritative boundary: session user
  может поставить writable system-config directory перед `/etc/xdg` через
  `XDG_CONFIG_DIRS`.
- XFCE reconciliation использует реальный session `xfconfd`; FIC не создаёт
  `XfceSystemBackend`, global contributions или locked system XML.

## Completed

- `XfceBackend` проверяет существующий locker командой
  `xfce4-screensaver-command --query` через session-scoped execution и не
  запускает daemon.
- Handler проверяет locker до state access и после convergence, управляет семью
  Xfconf properties, включая `/saver/fullscreen-inhibit=false`, и подтверждает
  изменения final readback.
- Сохранён `--set` -> `--create --type ... --set` fallback для отсутствующих
  properties.
- Добавлены handler/backend/global/static regressions и выполнены четыре
  обязательных negative controls с восстановлением production кода.

## Changed areas

- `XfceBackend` и `XfceScreenLockTimeoutHandler`.
- XFCE backend/session/global/static tests и CMake test registration.
- Desktop architecture и session-agent documentation.

## Validation

- Targeted build: `xfce_backend_tests`, `session_setting_reconciler_tests`,
  `screenlock_timeout_global_tests`, `session_aware_policy_tests` — passed.
- Targeted CTest: 5/5 passed, включая desktop-environment static check.
- Negative controls поймали отсутствие initial/final live checks,
  `/saver/fullscreen-inhibit` и ошибочный XFCE `MandatoryGlobal`.
- `git diff --check` — passed.
- Полная сборка проекта НЕ запускалась.

## Remaining

- Нет.
