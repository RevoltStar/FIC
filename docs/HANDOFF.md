# FIC: передача контекста

## Current base

- Дата: 2026-08-23.
- Ветка: `main`.
- Базовый commit задачи: `12c6a56`.

## Current task

- Управление `/etc/login.defs` и password aging существующих локальных
  accounts в `IDENTITY_ACCESS/PASSWORD_AGING`.

## Accepted architecture / invariants

- Operational policies используют существующие Required dependencies; они не
  вызывают config policies вручную и повторно читают фактический `login.defs`.
- `LoginDefsFileHandler` сохраняет чужие строки и fail-closed отклоняет
  duplicate/malformed target keys; запись атомарна, с reload/postcondition.
- Bulk обрабатывает только local passwd + structured local shadow accounts в
  `UID_MIN..UID_MAX`, всегда исключая root. Root имеет отдельную policy.
- Debian/Ubuntu читают `/etc/shadow`; ALT p11 использует per-user TCB. Запись
  выполняется только trusted profile-resolved `/usr/bin/chage`, без shell и
  без `-d`; `sp_lstchg` обязан остаться неизменным.
- `PASS_MAX_DAYS=-1` — vendor sentinel unlimited на ALT и допустим независимо
  от `PASS_MIN_DAYS`. Иначе проверяется MIN <= MAX; UID_MIN <= UID_MAX всегда.
- Separate MIN/MAX policies не образуют транзакцию coordinated transition:
  невалидный промежуточный state отклоняется; dependency core не расширялся.

## Completed

- Добавлены пять login.defs option policies и две operational policies с
  Required dependency declarations 5/3.
- Добавлены platform defaults/paths/shadow backend, `ExecutableId::Chage` и
  package-trust integration через общий resolver/all-executable registry.
- Default `IDENTITY_ACCESS.conf` генерируется для выбранного profile.
- Добавлены local shadow/TCB reader, полный preflight, idempotency,
  per-account postcondition и partial-failure stop.
- Добавлены handler/option/operational/dependency/platform/static tests и
  RU/EN localization.

## Changed areas

- `fic/src/modules/identity_access/submodules/password_aging/`;
- platform profiles/resolver и daemon policy registration;
- default IDENTITY_ACCESS config generation, localization, tests и architecture docs.

## Validation

- Ubuntu 24.04 full build — успешно.
- `password_aging_tests`, dependency planner, platform profile/static tests —
  успешно.
- ALT p11 configure, generated defaults и platform profile/static tests —
  успешно.
- Staged install содержит generated `IDENTITY_ACCESS.conf`, но не template —
  успешно.
- Полный CTest: 39 passed, 4 environment-dependent skipped; один известный
  несвязанный failure `ipc_protocol_validation_tests` для status request.

## Remaining

- Реальный system `chage` намеренно не запускался; runtime проверен через
  injected runner/reader и structured temporary passwd/shadow/TCB files.
- UID policy model ограничен текущим `IntPolicyTypeValue` (`INT_MAX`), хотя
  некоторые Linux ABI представляют более широкий `uid_t`; расширение общего
  GUI/IPC numeric contract не входило в эту задачу.
