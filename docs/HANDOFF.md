# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `6c12d4b`.

## Current task

- Строгий безысключительный разбор пользовательского device ID в `fic-cli`.

## Accepted architecture / invariants

- CLI принимает device ID только как полностью разобранный положительный
  decimal `int`; leading zero допустим, whitespace и ведущий `+` запрещены.
- Некорректный ID отклоняется до IPC. Device daemon schema и JSON fields не
  изменяются.

## Completed

- Добавлен единый `DeviceIdParser` на `std::from_chars`: требуется полный
  положительный decimal `int`, без trim, `+`, partial parsing и exceptions.
- На parser переведены `device get`, `children`, `set`, `ignore-hierarchy`,
  `children-control`, `reset`; invalid ID отклоняется до IPC request.
- Добавлены unit tests диапазона/формата и CLI subprocess regressions, включая
  mutation-команду и проверку отсутствия IPC attempt.

## Changed areas

- `fic-cli/src/DeviceIdParser*`, `fic-cli/src/main.cpp`, CLI CMake/tests.

## Validation

- Fresh reconfigure и full incremental build: passed в `/tmp/fic-de-build` с
  временными development headers/pkg-config metadata и реальной runtime
  `libsystemd.so.0`.
- 4 релевантных CLI/IPC tests: passed.
- CTest без уже сломанного в базовом HEAD `module_ui_static_checks`: 67 passed,
  1 environment-dependent test skipped, 0 failed.
- `git diff --check`: passed.

## Remaining

- `module_ui_static_checks` требует старую строку `saveChanges(..., error)`, хотя
  базовый HEAD уже использует `ApplyResult::error`; это вне scope текущей задачи.
- Повторить native configure/build без временных libsystemd headers после
  установки `libsystemd-dev`.
