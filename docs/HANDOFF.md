# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `2797d64`.
- Рабочее дерево: изменены `fic-gui/src/app/MainWindow.cpp`,
  `fic-gui/src/app/MainWindow.h` и этот `docs/HANDOFF.md`.

## Current task

- Вместо пустого окна `fic-gui` при недоступном policy daemon показывать
  центрированную кнопку `Обновить`, которая повторяет загрузку модулей.

## Accepted architecture / invariants

- GUI не запускает daemon сам и не меняет IPC contract.
- `PolicyService` остаётся тонким клиентом daemon API; fallback state живёт
  локально в `MainWindow`.

## Completed

- `MainWindow::addModules()` теперь очищает текущие tabs, а при ошибке
  `module_list` или `policy_list` показывает fallback-widget вместо пустого
  `QTabWidget`.
- Кнопка `Обновить` вызывает тот же `MainWindow::addModules()` retry path.
- `statusbar` скрыт, чтобы не оставлять пустую полосу снизу; текст последней
  ошибки доступен как tooltip кнопки `Обновить`.

## Changed areas

- `fic-gui/src/app/MainWindow.cpp`
- `fic-gui/src/app/MainWindow.h`
- `docs/HANDOFF.md`

## Validation

- `cmake --build build-xi-check --target fic-gui -j2` passed after the final
  `statusbar` hiding change.
- `git diff --check` passed.

## Remaining

- GUI runtime manually with daemon stopped was not launched in this workspace.
- No automated GUI interaction test was added.
