# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `00b7fd7`.

## Current task

- Сделать default и validation политики `sudo_securepath` platform-aware.

## Accepted architecture / invariants

- Политика сохраняет exact replacement semantics: заданный список полностью
  заменяет effective `Defaults secure_path`.
- Один CMake platform default формирует и `PlatformProfile`, и свежий
  immutable `DAC.conf`; существующий рабочий config при upgrade сохраняется.
- Validator запрещает отдельные `.`/`..`, relative, empty и ненормализованные
  path components, но допускает точки внутри обычных имён каталогов.

## Completed

- Подтверждены package defaults classic sudo для Debian 12/13, Ubuntu 24.04 и
  ALT p11, а также active sudo-rs для Ubuntu 26.04.
- Добавлены platform defaults для всех пяти поддерживаемых profiles.
- `DAC.conf` переведён в build-time template без изменения schema.
- Validator выделен в тестируемый тип и исправлен для dotted directory names.
- Семантика точной замены отражена в policy descriptions и архитектурной
  документации.

## Changed areas

- CMake platform selection и install rules.
- DAC sudo secure-path policy/type validator.
- Platform profile validation и generated default header.
- Default DAC config, локализация, profile/static/unit tests.

## Validation

- `platform_profile_tests` и `sudo_secure_path_policy_type_value_tests` — passed
  для Debian 12/13, Ubuntu 24.04/26.04 и ALT p11.
- `sudoers_configuration_tests` — passed для Ubuntu 26.04 build.
- `schema_contract_tests` — passed; Ubuntu 26.04 staged install содержит
  generated `DAC.conf` с `/snap/bin` и не содержит template.
- `python3 tests/fic/platform/static_checks.py .` — passed.
- Target `fic` — built для Ubuntu 26.04 и ALT p11.
- Active `/usr/lib/cargo/bin/visudo` sudo-rs 0.2.13 принял generated sudoers с
  platform default и dotted site-specific paths.

## Remaining

- Все шесть задач пользовательского списка завершены; implementation work не
  осталось.
- Real host policy apply намеренно не выполнялся.
