# FIC: передача контекста

## Current base

- Дата: 2026-08-24.
- Ветка: `main`.
- Базовый commit задачи: `b3a9c8d`.

## Current task

- Расширение PAM password-quality policies для дополнительных настроек
  `pam_pwquality`.

## Accepted architecture / invariants

- Новые policies используют существующий `PamOptionPolicy`, provider/effective
  PAM verification и canonical `PamPlatformConfig::passwordQualityConfigPath`.
- Логические FIC values хранятся без native encoding: `yes/no` преобразуются
  в `1/0`, minimum credit `N > 0` — в `-N`, а `0` — в native `0` внутри
  PAM option path.
- `enforce_for_root` остаётся беззначным flag; `password_min_classes`
  независима от четырёх minimum-credit policies.

## Completed

- Добавлены восемь policies: username/GECOS checks, quality enforcement for
  root, `difok` и четыре class minima.
- Добавлен небольшой двунаправленный `PamOptionValueCodec`; существующая flag
  abstraction переиспользована без изменения её семантики.
- Обновлены registry, default config, ru/en localization, README и static
  registration/config checks.
- Добавлены codec и policy-level tests с временным effective PAM graph,
  override failures, idempotency, flag и credit mappings.

## Changed areas

- `fic/src/modules/identity_access/submodules/pam/`;
- daemon policy registration;
- `IDENTITY_ACCESS.conf.in`, ru/en localization и PAM README;
- PAM/identity tests и platform static checks.

## Validation

- `cmake -S . -B build-hardening-ubuntu2404 -DFIC_TARGET_PLATFORM=ubuntu-24.04`
  — успешно.
- Targeted build `pam_configuration_tests`,
  `identity_policy_hierarchy_tests` и `fic` — успешно.
- Targeted PAM tests, `platform_profile_static_checks` и
  `pam_packaging_static_checks` — успешно.
- Full `cmake --build build-hardening-ubuntu2404 -j2` — успешно.
- Full CTest: 39 passed, 4 environment-dependent skipped; один unrelated
  failure `ipc_protocol_validation_tests` для request `status`.
- `git diff --check` — успешно до финального HANDOFF update.

## Remaining

- Реальный policy apply и смена паролей на host не запускались.
- Известный unrelated `ipc_protocol_validation_tests` остаётся красным.
