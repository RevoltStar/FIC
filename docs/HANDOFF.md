# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `54cfa7a`.

## Current task

- Совместимость executable pathname с line-based форматом `commandhash.txt`.

## Accepted architecture / invariants

- Filesystem path validation, storage-key validation и opened-object validation
  остаются отдельными этапами.
- `commandhash.txt` сохраняет формат `<path>=<sha256>` без migration/escaping.
- Target по-прежнему открывается один раз с
  `O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK`; `fstat`, execute-bit validation и
  SHA-256 выполняются по тому же fd.
- Общий `ConfigFileHandler` сохраняет прежнюю нормализацию key whitespace по
  умолчанию; exact whitespace включён только opt-in для `CommandHashStore`.

## Completed

- Storage keys fail-closed отклоняют ASCII controls `0x00..0x1F`, `0x7F`, `=`
  и `#` до open, store mutation/remove или verify lookup.
- Ошибка на запрещённый byte использует безопасные hex/symbolic diagnostics и
  не отражает raw pathname.
- Accepted pathname с повторными/крайними spaces, UTF-8 и `foo..bar` сохраняет
  exact key и проходит save/load/verify round-trip.
- Добавлены validator, daemon response, batch atomicity, removal и round-trip
  regressions.

## Changed areas

- `fic-common/fic-core`: opt-in key whitespace policy и `CommandHashStore`.
- Tests: command hash security/batch/handler и static contract.

## Validation

- Fresh configure и full build passed в
  `/tmp/fic-commandhash-key-build-20260906` с временной pkg-config metadata для
  доступной runtime `libsystemd.so.0`.
- Relevant command hash tests passed; root-only batch test отдельно passed через
  `unshare -Ur`.
- CTest вне sandbox без базово сломанного `module_ui_static_checks`: 69 passed,
  1 root-only test skipped, 0 failed.
- `git diff --check`: passed.

## Remaining

- `module_ui_static_checks` уже сломан в базовом HEAD: ожидает старую строку
  `saveChanges(..., error)`, тогда как код использует `ApplyResult::error`.
- Native configure без временной libsystemd pkg-config metadata требует
  установки development package `libsystemd-dev`.
