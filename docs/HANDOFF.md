# FIC: передача контекста

## Current base

- Дата: 2026-08-20.
- Ветка: `main`.
- Базовый commit задачи: `25e2cf5` (`Продолжаем актуализировать номера сборки`).

## Current task

- Очистка migration/legacy-state архитектуры перед первой публичной версией.

## Accepted architecture / invariants

- Product development version — `0.0.0-alpha`, первая stable — `0.1.0`.
- IPC, config schema и device DB schema имеют версию `1`; schema 1 является
  первой и единственной поддерживаемой схемой.
- Отсутствующие конфиги создаются из immutable defaults; существующие конфиги
  не перезаписываются и принимаются только с каноническим `_schema_version=1`.
- Отсутствующая/пустая device DB создаётся сразу как schema 1. Любая
  несовместимая непустая DB отклоняется без миграции и изменения.
- Package bootstrap: `ensure-config`, `initialize-db`, строгие `check-config` и
  `check-db`, затем обычные trust sync/start/health checks.

## Completed

- Удалены `UpgradeManager`, DB/config migration API, upgrade journal/state path,
  migration-only CLI и package steps.
- Удалены legacy DB fixture, `fic.timer`, `--oneshot` и deprecated alias
  `ModuleConfigFileHandler::isParameterExists()`.
- Добавлены `ConfigSchemaManager` и schema contract tests; device DB tests
  переведены на fresh schema 1 initialization.
- Документация и DEB/RPM lifecycle обновлены под strict first-release contract.

## Changed areas

- `fic-common/fic-core`, `fic-common/fic-device-db`;
- `fic`, `fic-dick`, CMake/install layout;
- `packaging/deb`, `packaging/rpm`;
- schema/device/static tests и документация.

## Validation

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build build-check -j2` — успешно.
- Полный `ctest --test-dir build-check --output-on-failure`: 39 тестов прошли
  или штатно пропущены, один несвязанный `ipc_protocol_validation_tests` упал
  на противоречивом существующем assertion для одинакового request JSON.
- `ctest --test-dir build-check --output-on-failure -E
  '^ipc_protocol_validation_tests$'` — 39/39 без ошибок; 3 host-dependent теста
  штатно пропущены.
- `git diff --check` — успешно.

## Remaining

- Текущий `tests/paths/IpcProtocolValidationTests.cpp` сначала принимает, а
  затем отвергает один и тот же `{"api_version":1,"command":"status"}`.
  Тест и IPC-контракт текущей задачей не изменялись; требуется отдельное
  исправление ожидания.
- Реальные package install/upgrade и privileged runtime операции не запускались.
