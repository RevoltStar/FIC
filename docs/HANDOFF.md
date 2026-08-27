# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `b43019f0d45df56212da3de23f3c6db9936eb8e3`.

## Current task

- Исправление ложного failure `OSS/screenlock_timeout` при read-back GNOME
  `gsettings` значений вида `uint32 N`.

## Accepted architecture / invariants

- GVariant textual syntax является GNOME-specific и не добавляется в общий
  `desktop_backend::parseInteger()`.
- KDE/XFCE/FLY продолжают использовать неизменённый generic integer parser.
- GNOME unsigned settings читаются через typed `GnomeBackend` API и строгий
  parser полного `uint32 N` representation.
- Session-agent, session resolution, command environment и daemon trust model
  этой задачей не меняются.

## Completed

- Добавлен `gnome_backend::parseGSettingsUInt32()` на `std::from_chars` с
  полной проверкой input, отрицательных значений и uint32 overflow.
- Добавлен `GnomeBackend::getUInt32Setting()` с parse diagnostic.
- `GnomeScreenLockTimeoutHandler` проверяет typed `idle-delay`/`lock-delay` и
  выдаёт отдельные parse/mismatch diagnostics с expected/actual.
- Generic `desktop_backend::parseInteger()` не изменён.
- Добавлены regression tests для реальных, whitespace, malformed и boundary
  GVariant значений.

## Changed areas

- `fic/src/modules/oss/desktop_environment/backends/`;
- `GnomeScreenLockTimeoutHandler.cpp`;
- relevant test и `tests/CMakeLists.txt`.

## Validation

- ALT p11 configure в `/tmp/fic-session-agent-build` — успешно.
- `fic` и `gsettings_value_parser_tests` — успешно собраны.
- Targeted parser test — успешно.
- Parser test отдельно собран и выполнен с `-Wall -Wextra -Werror`.
- Полная сборка проекта — успешно.
- Полный CTest из 50 tests: 45 passed, 4 sandbox-skipped, 1 существующий
  unrelated failure — `ipc_protocol_validation_tests` assertion об API v1.
- `git diff --check` — успешно.

## Remaining

- Новый daemon binary/RPM не устанавливался на `10.88.0.86`, поэтому повторный
  runtime `fic-cli policy apply OSS screenlock_timeout` после parser fix ещё не
  выполнен.
- До исправления на этой машине подтверждены правильные фактические values:
  `idle-delay=uint32 600`, `lock-enabled=true`, `lock-delay=uint32 0`; false
  failure был вызван разбором `32` из type name `uint32`.
- Существующий unrelated `ipc_protocol_validation_tests` failure не исправлялся.
