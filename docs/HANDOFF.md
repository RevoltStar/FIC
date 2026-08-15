# FIC: передача контекста

## Current base

- Дата: 2026-08-15.
- Ветка: `main`.
- Базовый commit задачи: `8a0b9f6` (`Исправить табличную разметку редактора политик`).

## Current task

- Устранена N+1-загрузка полного дерева устройств в `fic-gui` / `fic-dick`
  без изменения UI layout и внешнего вида.

## Accepted architecture / invariants

- Ручное раскрытие отдельной ветки остаётся lazy через `device_children` и
  точечный `device_attributes`.
- `Expand All`, checkbox/quick filter `История` и глобальные search/filter
  используют один flat `device_tree_snapshot` IPC request.
- Snapshot и его revision читаются в одной SQLite read transaction; основной
  recursive CTE возвращает устройства вместе с attributes.
- Effective policy snapshot вычисляется по in-memory indexes без SQL на каждый
  device. `device_events` остаётся отдельным API.

## Completed

- Добавлен DB snapshot с `WITH RECURSIVE`, сворачиванием attribute rows,
  current/history visibility, защитой от cycle/depth и fail-closed output.
- Добавлен read-only `device_tree_snapshot` с flat `parent_id`, attributes,
  effective fields, `revision`, `boot_id` и проверкой размера IPC response.
- GUI строит полное дерево локально из snapshot, явно передаёт attributes в
  name/icon rendering и сохраняет selection, expanded state и scroll position.
- Добавлены DB/IPC contract tests и архитектурные static checks.
- Обновлена `docs/architecture-diagrams.md` с lazy и full-snapshot режимами.

## Changed areas

- `fic-common/fic-device-db`;
- `fic-dick/src/core/DeviceTreeSnapshot.*` и daemon routing;
- `fic-gui/src/DeviceTree.*`;
- `tests/device-control`, `tests/CMakeLists.txt`;
- `docs/architecture-diagrams.md`.

## Validation

- `cmake -S . -B /tmp/fic-device-tree-snapshot-build
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build /tmp/fic-device-tree-snapshot-build -j2` — успешно.
- `ctest --test-dir /tmp/fic-device-tree-snapshot-build --output-on-failure` —
  36 passed, 3 host-dependent tests штатно пропущены, ошибок нет.
- Реальные device-control mutations/enforcement не запускались.

## Remaining

- Интерактивная проверка большого дерева в реальной GUI-сессии не выполнялась;
  layout и styling не изменялись.
