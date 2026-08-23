# FIC: передача контекста

## Current base

- Дата: 2026-08-23.
- Ветка: `main`.
- Базовый commit задачи: `e82dc19`.

## Current task

- Исправление semantic false positive в `PamControlFlowAnalyzer` для штатного
  `su`/`pam_rootok` и gate-модулей вроде `pam_succeed_if` без ослабления
  fail-closed проверки `required_pam_enforcement`.

## Accepted architecture / invariants

- Linux-PAM control actions продолжают обрабатываться независимо от semantic
  role модуля; role влияет только на credential evidence.
- `pam_rootok.so` является trusted authentication bypass только при совпадении
  явного platform-specific правила `service + module + reason` и реальном
  успешном завершении stack через `done`.
- Debian/Ubuntu доверяют `pam_rootok` в `su` и `su-l`; ALT p11 — только в `su`,
  согласно проверенной package topology.
- `pam_succeed_if` и остальные известные gate-модули не создают credential
  success/failure evidence, но их `sufficient`/extended controls по-прежнему
  могут создать настоящий bypass.
- Неизвестные модули, `pam_permit` и `pam_rootok` вне доверенного service
  остаются fail-closed.

## Completed

- Введены роли `CredentialAuthenticator`, `Gate`, `Enforcement`,
  `TrustedAuthenticator`, `Unknown` и точные outcomes для `pam_rootok` и
  `pam_succeed_if`.
- В `PamPlatformConfig` добавлены валидируемые trusted bypass rules; профили
  Debian 12/13, Ubuntu 24.04/26.04 и ALT p11 заполнены согласно их topology.
- Разрешённый путь не удаляется из symbolic state-space: analysis сохраняет
  service, module, reason, source line и trace.
- Добавлены regression-сценарии для `su`, `su-l`, `sshd/pam_rootok`, SDDM,
  gate success/failure и сломанного non-root failure-accounting path. Старые
  `pam_permit` и unknown-module bypass tests сохранены и проходят.
- На `172.17.1.150` read-only подтверждены Ubuntu `su` с
  `auth sufficient pam_rootok.so` и отдельный `su-l`, включающий `su`; систему
  и PAM-конфигурацию не изменяли.

## Changed areas

- `fic/src/modules/identity_access/submodules/pam/`;
- `fic/src/platform/` и PAM data поддерживаемых platform profiles;
- PAM и platform regression/static tests.

## Validation

- Целевой build `pam_configuration_tests`,
  `identity_policy_hierarchy_tests`, `platform_profile_tests` — успешно.
- Целевые PAM/policy/platform/static tests — 5/5 успешно.
- Fresh configure/build и `platform_profile_tests`: Debian 12, Debian 13 и
  ALT p11 — успешно; Ubuntu 24.04 active build — успешно.
- `cmake --build build-check -j2` — полный build успешно.
- Полный CTest active Ubuntu 24.04 build: 37 passed, 4 environment-dependent
  skipped; `pam_configuration_tests`, `identity_policy_hierarchy_tests` и
  `platform_profile_tests` прошли. Один несвязанный воспроизводимый failure:
  `ipc_protocol_validation_tests` assertion для status request.
- `git diff --check` — успешно до финального обновления HANDOFF.

## Remaining

- Новый build/package не развёртывался на `172.17.1.150`; реальный
  `fic-cli policy apply` после установки исправления не запускался.
- На хосте остаётся отдельный реальный `login` path с ранним отказом
  `pam_script.so`, который обходит `pam_faillock authfail` и может продолжить
  блокировать aggregate-policy. Текущее trusted bypass правило намеренно его
  не разрешает.
- Fresh Ubuntu 26.04 `platform_profile_tests` блокируется существующим в `HEAD`
  несоответствием DAC test/profile: профиль разрешает symlink targets для
  `/usr/bin/df` и `/usr/sbin/ip`, а общий test запрещает любые такие исключения
  у protected commands. PAM-изменение этого не затрагивает.
- Несвязанный `ipc_protocol_validation_tests` в scope задачи не исправлялся.
