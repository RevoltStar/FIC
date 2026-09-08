# FIC: передача контекста

## Current base

- Ветка `main`, родитель текущей правки `c3969dd`.

## Current task

- Устранить audit field injection в `fic` и `fic-dick`, переведя always-on
  security audit trail на bounded JSON Lines.

## Accepted architecture / invariants

- Общий `fic-core` строит authoritative `timestamp`, `component`, typed
  `peer`, ограничивает строки и запись, выполняет единственный `json::dump()`
  escaping и записывает одну JSONL-строку.
- Каждый daemon строит только собственный whitelist `request`; весь IPC request
  не копируется.
- Лимит строки — 240 байт, записи — 16 КиБ. Это сохраняет прежний device limit
  и не превышает `log_records` line limit.
- Audit остаётся always-on и не проходит через `Logger` filtering.
- Расширение `.txt` сохранено: `log_records` читает строки как opaque text и
  не парсит старый формат.

## Completed / Changed areas

- Добавлен `fic/core/logging/SecurityAudit` и явная CMake-зависимость
  `nlohmann_json` для `fic-core`.
- Добавлены component builders `AdminAudit` и `DeviceAudit`; старые
  `request_audit_summary`, sanitizers и `AuditLogValue` удалены.
- IPC, startup policy apply и session-ready audit entries переведены на JSON.
- Добавлены shared/admin/device regression tests для injection, whitelist,
  peer/result integrity, types, controls, UTF-8, JSONL и limits.
- Обновлены `fic/README.md`, `fic-dick/README.md` и architecture docs.

## Validation

- Fresh Ubuntu 24.04 configure в отдельном каталоге: passed.
- Полный build: passed.
- Targeted audit tests: 3/3 passed.
- Полный non-root CTest вне sandbox: 78/78 passed.
- В sandbox ожидаемо блокировались bind/trusted-root integration tests; вне
  sandbox те же tests passed.
- Build использует временный pkg-config/header stub для установленной runtime
  `libsystemd.so.0`; CI/package environments ставят настоящий dev package.
- `git diff --check`: passed.

## Remaining

- Root-only `command_hash_batch_tests` не запускался.
- Коммит не создавать без отдельного запроса пользователя.
