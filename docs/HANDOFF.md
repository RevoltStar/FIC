# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit corrective pass: `77d2c99`.
- Коммиты кода задачи: `ee3fb0d`, `1a1a601`, `ff0d841`.

## Current task

- Закрыты два `pam_pwquality` P2 finding: case-insensitive raw mutation и
  точная line-length boundary semantics libpwquality 1.4.5.

## Accepted architecture / invariants

- `PamOptionPolicy` делегирует raw state/mutation в `PamProviderConfigFile`;
  provider strategy, а не policy layer, выбирает native key matching.
- Pwquality assignment/flag keys сопоставляются ASCII case-insensitive;
  generic `PamOptionFile` по умолчанию остаётся case-sensitive.
- Case-variant assignments канонизируются в lowercase и получают одинаковое
  requested value; уже effective mixed-case flag не переписывается.
- `pam_pwquality` для target libpwquality 1.4.5 вычисляется из native defaults,
  lexical `pwquality.conf.d/*.conf`, main config и argv каждой invocation.
- Pwquality config принимает максимум 1022 non-newline bytes в строке;
  1023-byte строка malformed и перед newline, и в exact EOF boundary.
- Prospective evaluator, raw mutation и final evaluator согласованы для
  case variants; transaction/rollback contract не изменён.

## Completed

- Добавлен provider-specific raw config dispatch без pwquality branching в
  policy class.
- `PamOptionFile` параметризован key-match mode с case-sensitive default.
- Исправлена boundary проверка, соответствующая upstream `fgets(char[1024])`.
- Добавлены production apply и evaluator boundary regression tests.

## Changed areas

- `fic/src/modules/identity_access/pam/`.
- PAM hierarchy/config tests и их CMake wiring.
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
- Tests-first запуск воспроизвёл case-sensitive assignment gap и ошибочное
  принятие 1023-byte newline-terminated строки.
- `git diff --check` пройден.

## Remaining

- Live libpwquality/PAM apply не запускался; host PAM не изменялся.
- Полная сборка всех executables и полный CTest не запускались; проверены daemon
  и непосредственно затронутые tests на всех profiles.
