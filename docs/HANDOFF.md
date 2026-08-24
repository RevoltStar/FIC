# FIC: передача контекста

## Current base

- Дата: 2026-08-24.
- Ветка: `main`.
- Базовый commit задачи: `4dd9ac6`.

## Current task

- Security/correctness hardening существующих `/etc/login.defs` и password
  aging policies без добавления новых policies.

## Accepted architecture / invariants

- Passwd/shadow/TCB читаются строгим построчным parser; malformed/duplicate
  physical record блокирует весь preflight.
- TCB traversal descriptor-relative: TCB root, account directory и `shadow`
  открываются с `O_NOFOLLOW`; `.`/`..`/slash/NUL как path component запрещены.
- Bulk исключает все UID 0 и до первого `chage` требует shadow state каждого
  eligible account. Root policy покрывает все локальные accounts с UID 0.
- `PasswordAgingPolicyDefaults` отделены от explicit missing-key semantics:
  отсутствующие PASS peers имеют shadow-utils sentinel `-1`, отсутствующие UID
  peers отклоняются fail-closed. Operational policies fallback не используют.
- CMake platform constants — единый источник policy defaults для generated
  config и generated C++ header. Debian/Ubuntu: `0/99999/7/1000/60000`; ALT
  p11: `0/99999/7/500/60000`; statuses остаются `DISABLE`.
- UID model использует `uid_t` и `UnsignedIntegerPolicyTypeValue` до
  `numeric_limits<uid_t>::max()`; GUI передаёт значение строкой через line edit.
- Required dependencies и trusted `chage -m/-M/-W -- USER` architecture не
  изменены; `sp_lstchg` остаётся неизменным.

## Completed

- Исправлены malformed `login.defs` occurrences и relation validation.
- Реализованы strict passwd/shadow parsers и secure TCB traversal.
- Добавлен двухфазный passwd/shadow consistency preflight и UID 0 semantics.
- Устранено дублирование platform defaults, исправлены ALT defaults и unsigned
  UID round-trip в policy metadata/GUI.
- Добавлены regression tests и обновлены localization/architecture docs.

## Changed areas

- `fic/src/modules/identity_access/submodules/password_aging/`;
- platform profile/default generation и `fic-policy` numeric types;
- GUI policy editor, localization, password-aging/platform tests и docs.

## Validation

- Targeted password-aging, dependency planner, platform profile/static tests —
  успешно на Debian 12/13, Ubuntu 24.04 и ALT p11; password-aging/static —
  успешно на Ubuntu 26.04.
- Full build Ubuntu 24.04 и Debian 12 — успешно.
- `fic` + password-aging/platform targets: Debian 13, Ubuntu 26.04, ALT p11 —
  успешно; GUI собран на Ubuntu 24.04 и Debian 13.
- Generated defaults/statuses всех пяти profiles проверены; ALT содержит
  `0/99999/7/500/60000`, все семь policies `DISABLE`.
- Full Ubuntu 24.04 CTest: 39 passed, 4 environment-dependent skipped, один
  известный несвязанный failure `ipc_protocol_validation_tests` для status.
- `git diff --check` — успешно.

## Remaining

- `platform_profile_tests` на Ubuntu 26.04 имеет существующий до этой задачи
  конфликт: профиль разрешает `/usr/sbin/ip -> /usr/bin/ip`, а общий тест
  запрещает symlink exceptions для protected commands. Не исправлялся как
  unrelated scope.
- Реальный system `chage` намеренно не запускался; runtime проверен injected
  runner/reader и temporary passwd/shadow/TCB trees.
