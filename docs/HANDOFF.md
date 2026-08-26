# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `e190798f716384aa4383664ff98db7fd8fbf1034`.

## Current task

- Миграция repository layout на domain/feature-first архитектуру без изменения
  runtime contracts и поведения.

## Accepted architecture / invariants

- Верхнеуровневые process и library boundaries не изменены.
- `fic-core` остаётся одной библиотекой, но внутренне разделён по
  ответственности; public include paths содержат соответствующий
  domain-каталог.
- В daemon source layout нет `submodules`: feature определяется путём
  `modules/<module>/<feature>`.
- GUI использует `app`, `shared` и feature-first `features`; `fic-dick`
  разделён на `daemon`, `device`, `policy`, `enforcement`, `collectors`.
- Runtime resources находятся в `fic/src/resources`; tests зеркалируют
  production domains, integration-сценарии находятся в `tests/integration`.

## Completed

- Перенесены daemon, common, GUI, device-control и test sources в целевые
  каталоги.
- Обновлены include paths, CMake source/resource references, packaging/static
  checks и relevant documentation.
- Production behavior, IPC, policy/config/DB schemas и version contracts не
  изменялись.

## Changed areas

- `fic-common/fic-core/`, `fic/src/`, `fic-gui/src/`, `fic-dick/src/`;
- `tests/`, component CMake files и packaging path references;
- `AGENTS.md`, component README и `docs/architecture-diagrams.md`.

## Validation

- `cmake -S . -B /tmp/fic-architecture-build -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build /tmp/fic-architecture-build -j2` — успешно.
- Staging install через `DESTDIR=/tmp/fic-architecture-stage` — успешно;
  binaries, public headers и runtime resources установлены.
- Targeted rerun исправленных static/packaging/version tests — 4/4 успешно;
  отдельный финальный `path_layout_static_checks` — успешно.
- Финальный полный CTest: 41 passed, 4 skipped, 1 существующий unrelated
  failure — `ipc_protocol_validation_tests` assertion в
  `tests/common/ipc/IpcProtocolValidationTests.cpp:18`.

## Remaining

- Runtime/privileged policy apply и device mutation не выполнять.
