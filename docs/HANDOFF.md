# FIC: передача контекста

## Current base

- Дата: 2026-08-20.
- Ветка: `main`.
- Базовый commit задачи: `618f51d` (`Минорные правки в README.md`).

## Current task

- UX-разделение сохранения desired policy configuration и немедленного
  `apply_module` в GUI.

## Accepted architecture / invariants

- `PolicyService::saveChanges()` является единственным GUI-путём сохранения
  value и ENABLE/DISABLE. `saveAndApplyChanges()` вызывает его и только после
  полного успеха отправляет существующий `apply_module`.
- Ошибка применения не откатывает уже сохранённую конфигурацию.

## Completed

- В `PolicyEditorWidget` одна кнопка заменена на локализованные «Сохранить» и
  «Сохранить и применить» с общим сбором и валидацией `PolicyChange`.
- `PolicyServiceTests` покрывают save-only, save+apply, ошибки каждого шага
  сохранения и ошибку применения без rollback.

## Changed areas

- `fic-gui/src/services/PolicyService.*`, `fic-gui/src/widgets/PolicyEditorWidget.cpp`;
- `fic/src/scripts/lang/{ru,en}.lang`, module-ui tests и GUI-документация.

## Validation

- `cmake --build build-check --target policy_service_tests fic-gui -j2` —
  успешно.
- Module-ui CTest (`module_ui_static_checks`, registry/descriptor/service tests)
  — 5/5 успешно.
- Полный `ctest --test-dir build-check --output-on-failure`: 39 тестов прошли
  или штатно пропущены, один несвязанный `ipc_protocol_validation_tests` упал
  на противоречивом существующем assertion для одинакового request JSON.
- `git diff --check` — успешно.

## Remaining

- Текущий `tests/paths/IpcProtocolValidationTests.cpp` сначала принимает, а
  затем отвергает один и тот же `{"api_version":1,"command":"status"}`.
  Тест и IPC-контракт текущей задачей не изменялись; требуется отдельное
  исправление ожидания.
