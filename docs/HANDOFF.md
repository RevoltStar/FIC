# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `e190798f716384aa4383664ff98db7fd8fbf1034`.

## Current task

- `IDENTITY_ACCESS/USER_CREATION:user_default_supplementary_groups` с
  provider-specific backend для defaults будущих локальных пользователей.

## Accepted architecture / invariants

- Одна logical policy использует отдельную
  `UserSupplementaryGroupsProviderKind`, не изменяя provider первых шести
  `USER_CREATION` policy.
- Debian 12 и Ubuntu 24.04 управляются через `ADD_EXTRA_GROUPS` и
  `EXTRA_GROUPS` в `/etc/adduser.conf`; Debian 13 и Ubuntu 26.04 — через
  `GROUPS` в `/etc/default/useradd`.
- ALT p11 `alterator-users 10.25-alt1` имеет additive-only
  `default-groups.d`, не выражающий exact replacement или empty list, поэтому
  profile явно `Unsupported` и apply завершается без записи.
- Значение хранится canonical JSON array; empty list удаляет shadow `GROUPS`
  либо задаёт `ADD_EXTRA_GROUPS=0`. Отсутствующие local groups и
  duplicate/malformed native targets отклоняются до mutation.

## Completed

- Добавлены policy/value type, provider mapping, daemon/config/localization
  wiring и architecture documentation.
- Добавлены специализированный atomic `/etc/adduser.conf` handler,
  `UseraddDefaultsFileHandler::removeValue()` и reusable local group helper.
- Добавлены runtime, profile и static/contract tests, включая empty state,
  idempotency, ambiguous config, unsafe paths и atomic two-key update.

## Changed areas

- `fic/src/modules/identity_access/configuration/` и
  `submodules/user_creation/`;
- platform profiles, daemon registration, config/localization resources;
- identity/platform/static tests и `docs/architecture-diagrams.md`.

## Validation

- Полная сборка Debian 13 profile в `/tmp/fic-supp-groups-build` — успешно.
- Targeted CTest (`user_creation_tests`, `platform_profile_tests`,
  `platform_profile_static_checks`) — 3/3 успешно.
- Полный CTest — 41 passed, 4 skipped, 1 unrelated existing failure:
  `ipc_protocol_validation_tests` assertion в
  `tests/paths/IpcProtocolValidationTests.cpp:18`.
- Compile-time provider mapping probe прошёл для Debian 12/13, Ubuntu
  24.04/26.04 и ALT p11. Полный Ubuntu 26.04 `platform_profile_tests`
  останавливается на существующем unrelated symlink-exception invariant для
  `/usr/bin/df`; новые mapping assertions не являются причиной ошибки.

## Remaining

- Реальный policy apply и создание test account не выполнялись; host accounts
  и `/etc` не изменялись.
- ALT остаётся намеренно unsupported до появления native override semantics,
  способной выразить replacement и empty list.
- Unrelated IPC и Ubuntu 26.04 profile baseline failures не исправлялись.
