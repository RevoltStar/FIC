# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit corrective pass: `02c16a6`.
- Коммиты кода задачи: `b599f8c`, `7378633`.

## Current task

- Закрыт последний известный `pam_pwquality` P2: raw mutation SET-style config
  directives совпадает с native libpwquality 1.4.5 presence semantics.

## Accepted architecture / invariants

- `PamOptionPolicy` делегирует raw state/mutation в `PamProviderConfigFile`;
  provider strategy, а не policy layer, выбирает native key matching.
- Pwquality использует `AsciiCaseInsensitive` + `SetPresence`: bare directive,
  assignment с любым value и whitespace-value form означают enabled.
- Policy `yes` принимает любое active SET occurrence без duplicate/write;
  policy `no` neutralizes все case-insensitive occurrences.
- Generic providers сохраняют case-sensitive `BareOnly`; passwdqc не изменён.
- Final provider semantic postcondition и transaction contract сохранены.

## Completed

- Добавлен explicit `PamOptionFlagSyntax::{BareOnly,SetPresence}`.
- Provider strategy выбирает `SetPresence` только для pwquality backend.
- Добавлены production apply tests для idempotent enable и полного disable
  bare/assignment case variants.

## Changed areas

- `fic/src/modules/identity_access/pam/`.
- PAM hierarchy production-path tests.
- PAM architecture documentation.

## Validation

- Для Debian 12/13, Ubuntu 24.04/26.04 и ALT p11 собран target `fic`.
- На каждом из пяти profiles последовательно прошли 8/8 tests:
  `platform_profile_static_checks`, `pam_packaging_static_checks`,
  `pam_configuration_tests`, `passwdqc_config_file_tests`,
  `alt_pam_faillock_topology_tests`, `identity_policy_hierarchy_tests`,
  `platform_profile_tests`, `pam_policy_defaults_tests`.
- Configure использовал только pkg-config stub для отсутствующего на host
  `libsystemd`; `fic-session-agent` этой матрицей не собирался.
- Tests-first запуск воспроизвёл ошибочное `malformed PAM flag` на валидном
  pwquality SET assignment.
- `git diff --check` пройден.

## Remaining

- Live libpwquality/PAM apply не запускался; host PAM не изменялся.
- Полная сборка всех executables и полный CTest не запускались; проверены daemon
  и непосредственно затронутые tests на всех profiles.
