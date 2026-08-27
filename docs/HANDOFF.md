# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `3600419733c7514501088c59305ac880e62e999c`.

## Current task

- Переименование `disable_videodisplay_when_locked` в
  `disable_kde_lock_screen_media_controls` и ограничение применения активными
  графическими KDE-сессиями.

## Accepted architecture / invariants

- Policy применяет `showMediaControls=false` только к активным графическим
  KDE-сессиям, независимо от способа их запуска.
- Сессии других desktop environment и с неизвестным desktop находятся вне
  области действия и не влияют на итоговый результат.
- Нет активных KDE-сессий — успешный результат/not applicable; ошибка хотя бы
  в одной KDE-сессии — общий failure.
- KDE backend сохраняет запись и readback `kscreenlockerrc`, затем вызывает
  существующий DBus reload.

## Completed

- Policy, config и localization keys переименованы.
- `SessionLocator::activeGraphicalSessions` теперь отбирает `Active=yes` и не
  исключает remote sessions.
- Применение разделено по KDE applicability с агрегацией результатов только
  применимых сессий.
- Добавлены шесть regression-сценариев и static checks контракта.

## Changed areas

- `fic/src/modules/oss/desktop_environment/policies/`;
- daemon policy registration;
- `fic/src/session/SessionLocator.cpp`;
- OSS config и `ru`/`en` localization;
- relevant CMake tests и platform static checks.

## Validation

- Targeted build нового test target — успешно.
- Targeted CTest из 4 tests — успешно.
- Полная ALT p11 build — успешно.
- Полный CTest из 52 tests: 47 passed, 4 environment-skipped, 1 existing unrelated
  failure `ipc_protocol_validation_tests` (устаревшее ожидание reject API v1).
- Все static checks прошли.
- `git diff --check` — успешно.

## Remaining

- Изменения текущей задачи не закоммичены.
- Existing unrelated `ipc_protocol_validation_tests` failure не исправлялся.
