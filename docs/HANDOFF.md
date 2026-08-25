# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `e114c85`.

## Current task

- Политики `IDENTITY_ACCESS/USER_CREATION` для defaults будущих локальных
  пользователей backend `shadow-utils useradd`.

## Accepted architecture / invariants

- Daemon изменяет только `/etc/default/useradd` (`HOME`, `SKEL`, `SHELL`,
  `GROUP`) и `/etc/login.defs` (`CREATE_HOME`, `USERGROUPS_ENAB`).
- Политики не создают пользователей, группы или каталоги и не меняют
  существующие accounts; frontend-specific и supplementary-group defaults вне
  scope.
- Native config duplicate/malformed target, unsafe path, отсутствующая local
  group и неэффективный shell отклоняются fail-closed до записи.
- Debian/Ubuntu defaults: `CREATE_HOME=no`, `SHELL=/bin/sh`; ALT p11:
  `CREATE_HOME=yes`, `SHELL=/bin/bash`. Во всех profiles `GROUP` представлен
  именем `users`, а не vendor numeric GID 100.

## Completed

- Добавлены шесть policy, registry/config/localization wiring и
  `UserCreationPlatformConfig` для всех пяти compile-time profiles.
- `LoginDefsFileHandler` перенесён в общий identity configuration layer без
  изменения состояний `Missing/Unique/Duplicate/Malformed`.
- Добавлен специализированный `UseraddDefaultsFileHandler` с точным native
  `KEY=value` syntax, сохранением неизвестных строк и atomic write.
- Добавлены runtime/static/profile tests и описание backend boundary.

## Changed areas

- `fic/src/modules/identity_access/configuration/` и
  `submodules/user_creation/`;
- platform profile/default generation и `IDENTITY_ACCESS.conf.in`;
- daemon registration, localization, identity/platform tests;
- `docs/architecture-diagrams.md`.

## Validation

- Полная Ubuntu 24.04 configure/build в `/tmp/fic-user-creation-build` —
  успешно.
- Targeted CTest subset: 5/5 успешно (`user_creation`, password-aging
  regression, platform runtime/static, packaging resource).
- `user_creation_tests` для Debian 12/13, Ubuntu 24.04/26.04 и ALT p11 — 5/5
  успешно; новые `platform_profile_tests` assertions прошли во всех profiles.
- Полный CTest: 45 tests passed/skipped as configured, один unrelated failure
  в существующем `ipc_protocol_validation_tests` из-за противоречивых
  assertions для одного и того же API v1 request.

## Remaining

- Реальный policy apply и создание test account не запускались: validation не
  меняла host accounts или `/etc`.
- Отдельный полный `platform_profile_tests` на Ubuntu 26.04 останавливается на
  существующем unrelated invariant про symlink exceptions у protected command;
  новые user-creation assertions выполняются раньше и проходят.
- Существующий IPC test failure не исправлялся как unrelated scope.
