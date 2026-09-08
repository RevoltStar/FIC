# FIC: передача контекста

## Current base

- Ветка: `main`, commit `48815b5` (fd-bound verified execution).
- До текущей задачи рабочее дерево было чистым.

## Current task

- Усиление `sanitize_log_value()` для untrusted значений security audit log.

## Accepted architecture / invariants

- `\n`, `\r`, `\t` заменяются пробелами; остальные C0 и DEL — видимыми
  `\xNN` с uppercase hex. Кавычка и обратный слеш экранируются.
- Обход по `unsigned char`; байты >= 0x80 сохраняются без изменений.
- Структура audit-записей, места sanitization и always-on audit path сохранены.
  Helper вынесен во внутренний `fic/src/daemon/AuditLogValue.h` для прямых тестов;
  unrelated logging code не менялся.

## Completed / Changed areas

- `fic/src/main.cpp`, `fic/src/daemon/AuditLogValue.h`: усиленный sanitizer.
- `tests/fic/daemon/AuditLogValueTests.cpp`, `tests/CMakeLists.txt`: regression
  cases ESC/BEL/NUL/DEL, whitespace, quotes/backslashes, ASCII, UTF-8, ANSI,
  смешанные значения; exhaustive C0 и high bytes, однострочность quoted field.

## Validation

- Configure: `PKG_CONFIG_PATH=/tmp/fic-dev-tree/pkgconfig cmake -S . -B
  /tmp/fic-dev-build -DFIC_TARGET_PLATFORM=ubuntu-24.04`: success.
- `cmake --build /tmp/fic-dev-build --target fic audit_log_value_tests -j2`: success.
- Targeted CTest: `audit_log_value_tests`, `platform_profile_static_checks`,
  `path_layout_static_checks`: 3/3 passed.
- `python3 tests/fic/platform/static_checks.py .`,
  `python3 tests/common/static_checks.py .`: success.
- Тот же regression отдельно собран и выполнен с `-fsigned-char` и
  `-funsigned-char` (`-std=c++17 -Wall -Wextra -Werror -DNDEBUG`): оба passed.
- Negative control: тест с прежним sanitizer, отдельно собранный в `/tmp`,
  падает на проверке ожидаемого escaping; production sources не подменялись.
- Финальный diff review выполнен; `git diff --check`: clean.

## Remaining

- Незавершённых изменений по задаче нет. Full build/CTest и реальный daemon
  runtime не запускались: изменение локально для sanitizer и его callers.
- Targeted build использует существующий stub libsystemd в `/tmp/fic-dev-tree/*`.
- Коммит не создавать без отдельного запроса пользователя.
