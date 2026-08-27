# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `8ae9bf6ae016c2acb6c4ae35adbb4cc1c5c5288b`.

## Current task

- Platform-specific default и поддержка `pam_passwdqc` в policy
  `required_pam_enforcement`.

## Accepted architecture / invariants

- `FIC_REQUIRED_PAM_ENFORCEMENT_DEFAULT` в `FicTargetPlatform.cmake` — единый
  source of truth для compiled policy metadata и generated
  `IDENTITY_ACCESS.conf`.
- Default для ALT p11: `pam_faillock,pam_passwdqc`; для Debian/Ubuntu:
  `pam_faillock,pam_pwquality,pam_pwhistory`.
- Recognized providers не ограничиваются default текущей платформы.
- Existing working configs не мигрируются и не переписываются; schema version
  не меняется.
- Individual password-quality option policies остаются привязаны к semantics
  `pam_pwquality`; ALT passwdqc option mapping вне scope.

## Completed

- Generated platform default подключён к policy metadata и config template.
- Parser принимает, нормализует и deduplicate-ит `pam_passwdqc`.
- Restriction metadata использует общий список supported provider names.
- `RequiredPamEnforcementPolicy` проверяет `PamPasswdqc` как
  `PasswordQuality` на `platform.passwordServices`.
- Добавлены parser, positive/negative verifier, metadata и generated-default
  regression tests.

## Changed areas

- `cmake/FicTargetPlatform.cmake`, generated platform defaults и `fic/CMakeLists.txt`;
- `fic/src/modules/identity_access/pam/`;
- `fic/src/resources/config/IDENTITY_ACCESS.conf.in` и descriptions;
- PAM/platform tests и static checks.

## Validation

- ALT p11 targeted PAM/platform/static tests — успешно.
- `identity_policy_hierarchy_tests` для ALT p11, Debian 12/13 и Ubuntu
  24.04/26.04 — успешно; каждый profile проверяет exact generated default,
  status `DISABLE` и equality с policy metadata.
- `platform_profile_tests` — успешно для ALT p11, Debian 12/13, Ubuntu 24.04;
  Ubuntu 26.04 сохраняет unrelated existing failure про protected-command
  symlink exceptions.
- Полная ALT p11 build — успешно.
- Полный ALT p11 CTest: 45 passed, 4 sandbox-skipped, 1 existing unrelated
  failure `ipc_protocol_validation_tests` (устаревшее ожидание reject API v1).
- `pam_configuration_tests`, `identity_policy_hierarchy_tests`,
  `platform_profile_static_checks`, `pam_packaging_static_checks` — успешно.

## Remaining

- Runtime distro-container tests не выполнялись; все пять generated build
  profiles проверены локальными configure/build tests.
- Миграций нет: уже сохранённое administrator value остаётся без изменений.
- Поддержка passwdqc-specific option policies является отдельной будущей
  задачей.
