# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `7934e18`.

## Current task

- Перевести основной `fic.service` с `Type=simple` на `Type=notify`.

## Accepted architecture / invariants

- `READY=1` отправляется только после успешной registry initialization,
  завершения startup policy apply и успешного `listen()` admin socket.
- Ошибки отдельных startup policies остаются non-fatal и отражаются в
  readiness `STATUS`; fatal startup errors завершают процесс до `READY=1`.
- `sd_notify()` не влияет на direct run без `NOTIFY_SOCKET`.
- `fic-device.service` остаётся `Type=simple` и зависит от готовности
  `fic.service` через существующие `After`/`Requires` без обратной зависимости.

## Completed

- Основной `fic` напрямую связан с `libsystemd` через imported pkg-config
  target и отправляет phase `STATUS` плюс итоговый `READY=1`.
- `fic.service` использует `Type=notify` и `TimeoutStartSec=120s`.
- Static contract фиксирует linkage, unit types, dependency graph и порядок
  readiness lifecycle.
- Packaging `wait-daemon` health checks не изменялись.

## Changed areas

- `fic/CMakeLists.txt`, daemon startup в `fic/src/main.cpp`.
- `fic.service.in` и `tests/common/static_checks.py`.

## Validation

- `python3 tests/common/static_checks.py .` — passed.
- `python3 tests/fic/platform/static_checks.py .` — passed.
- Fresh Ubuntu 26.04 CMake configure и target `fic` build — passed;
  `libsystemd 257` найден, бинарник связан с `libsystemd.so.0`.
- Direct `fic --version` без `NOTIFY_SOCKET` — passed.
- Generated `fic.service`/`fic-device.service`: `systemd-analyze verify` — exit
  0; sandbox выдал только non-fatal socket-option warnings.

## Remaining

- Implementation work не осталось.
- Полный CTest и реальный systemd startup не выполнялись.
