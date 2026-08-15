# FIC: передача контекста

## Current base

- Дата: 2026-08-15.
- Ветка: `main`.
- Базовый commit задачи: `dd79dcd` (`Актуализируем AGENTS.md`).

## Current task

- Исправлена UI-регрессия табличной разметки общего `PolicyEditorWidget` без
  возврата policy UI в `MainWindow` и без изменения business logic.

## Accepted architecture / invariants

- Один `PolicyEditorWidget` остаётся общим для `StandardModulePage`, настроек
  `AuditModulePage` и общих правил `DeviceModulePage`.
- Рамки принадлежат только контейнерам табличных ячеек. Native styling
  вложенных editors не переопределяется каскадным stylesheet.
- Header и submodule backgrounds используют Qt palette roles и должны
  оставаться читаемыми в light/dark themes.

## Completed

- Header, submodule и четыре элемента каждой policy row помещены в отдельные
  `QFrame::StyledPanel` cells с внутренними margins.
- Внешний content frame снова визуально объединяет таблицу; submodule header
  занимает все четыре колонки.
- Колонки получили stretch `0/1/1/2` и minimum widths для enabled/name/value.
  Пустое пространство забирает отдельная stretch-row после всех policies.
- Multiline value editor и read-only description имеют ограниченную высоту;
  длинный текст прокручивается внутри.
- `Apply` остаётся вне scroll content в отдельном layout с внешними margins.
- `module_ui_static_checks` проверяет cell containers, palette-aware frames,
  нижнюю stretch-row и отсутствие прямого размещения policy controls в root
  grid или каскадного stylesheet.

## Changed areas

- `fic-gui/src/widgets/PolicyEditorWidget.cpp`;
- `tests/module-ui/static_checks.py`;
- `docs/HANDOFF.md`.

## Validation

- `cmake -S . -B /tmp/fic-policy-ui-build
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build /tmp/fic-policy-ui-build -j2` — успешно.
- `ctest --test-dir /tmp/fic-policy-ui-build --output-on-failure` — 38/38 без
  ошибок; `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` штатно пропущены как host-dependent.
- Safe smoke: `fic-gui` с `QT_QPA_PLATFORM=offscreen` и отсутствующим
  тестовым socket вошёл в event loop и был остановлен `timeout` через 3 секунды
  (`124`).
- Offscreen visual preview настоящего `PolicyEditorWidget` просмотрен для
  synthetic `GLOBAL`, `NET`, `DAC`, `DC`, `AUDIT` descriptors в light и dark
  palettes. Проверены рамки, геометрия строк, multiline editors и отделение
  `Apply`; screenshots остались только в `/tmp/fic-policy-ui-preview`.
- `git diff --check` — успешно.

## Remaining

- Интерактивная проверка в реальной desktop theme/VNC не выполнялась;
  offscreen preview подтверждает отрисовку и геометрию, но не заменяет полный
  пользовательский workflow.
- Реальный daemon и policy mutations/apply не запускались.
