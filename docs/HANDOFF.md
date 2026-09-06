# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `b2c32ca`.

## Current task

- Безопасная fd-based валидация и SHA-256 hashing executable paths в
  `CommandHashStore`/`calc_hash`.

## Accepted architecture / invariants

- Path syntax проверяется component-aware; final symlink запрещён, intermediate
  symlink-компоненты разрешены для совместимости с distro layouts.
- Target открывается один раз с `O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK`, затем тот же
  fd проходит `fstat`, regular/execute-bit validation и SHA-256 read.
- Формат/path hash store и SHA-256 algorithm не изменены; batch update остаётся
  all-inputs-before-store-mutation.

## Completed

- `CommandHashStore` переведён с `lstat`/`ifstream` на RAII fd-based open/fstat/read.
- FIFO/device/directory/non-executable/final-symlink paths отклоняются; FIFO
  open не блокируется.
- `calc_hash` handler возвращает безопасную причину ошибки клиенту.
- Добавлены security, handler, path syntax, deterministic pathname-replacement
  TOCTOU и batch atomicity regressions.

## Changed areas

- `fic-common/fic-core` integrity store, daemon `calc_hash` routing,
  architecture docs и tests.

## Validation

- Fresh configure и full build: passed в `/tmp/fic-hash-build` с
  временными development headers/pkg-config metadata и реальной runtime
  `libsystemd.so.0`.
- Relevant hash/static/handler tests: passed; normal CTest root-only batch test
  skipped, затем отдельно passed через `unshare -Ur`.
- CTest без уже сломанного в базовом HEAD `module_ui_static_checks`: 69 passed,
  1 environment-dependent test skipped, 0 failed.
- `git diff --check`: passed.

## Remaining

- `module_ui_static_checks` требует старую строку `saveChanges(..., error)`, хотя
  базовый HEAD уже использует `ApplyResult::error`; это вне scope текущей задачи.
- Повторить native configure/build без временных libsystemd headers после
  установки `libsystemd-dev`.
