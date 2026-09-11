# FIC: передача контекста

## Current base

- Ветка `main`.
- База до текущего corrective commit: `50bef33`.

## Current task

- Исправить false success XFCE `screenlock_timeout` при signed или malformed
  integer readback.

## Accepted architecture / invariants

- GNOME и FLY — `MandatoryGlobal`; KDE и XFCE — `SessionOnly`; LXQt —
  `Unsupported`.
- XFCE handler управляет прежними семью Xfconf properties и сохраняет live
  `xfce4-screensaver-command --query` checks.
- Integer readback обеих XFCE delay properties разбирается строго: после trim
  учитывается знак и требуется полное потребление непустой строки.

## Completed

- Добавлен локальный XFCE strict integer parser; общий
  `desktop_backend::parseInteger()` не изменён.
- `/saver/idle-activation/delay` и `/lock/saver-activation/delay` сравниваются
  через strict parser.
- Добавлены regressions для `-5`, malformed suffix/prefix, whitespace и обеих
  delay properties.

## Changed areas

- `XfceScreenLockTimeoutHandler`.
- `SessionSettingReconcilerTests`.

## Validation

- Targeted build: `session_setting_reconciler_tests`,
  `screenlock_timeout_global_tests`, `xfce_backend_tests` — passed.
- Targeted CTest: 4/4 passed, включая
  `desktop_environment_architecture_static_checks`.
- Negative control со старым loose parsing упал на regression `-5` с
  `negative XFCE idle delay was accepted as matching`; strict-код восстановлен.
- `git diff --check` — passed.
- Полная сборка проекта НЕ запускалась.

## Remaining

- Нет.
