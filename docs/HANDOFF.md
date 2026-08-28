# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `354725f`.
- Реализация: `9158bd2`, `4d600cc`.

## Current task

- Review-fixes capability-oriented PAM: required passwdqc external config,
  effective native evaluation, full policy rollback и extensible defaults.

## Accepted architecture / invariants

- `PamProviderCatalog` — single source provider capability/module/grammar,
  external config contract и policy bindings; platform выбирает composition.
- Для managed passwdqc PAM argument `config=` required; `conf=` текущих
  key/value providers optional.
- Passwdqc state вычисляется последовательно и рекурсивно с native last-wins
  semantics; ambiguous/unsafe/unknown state отклоняется fail-closed.
- `PamOptionPolicy` откатывает raw config и metadata при любой ошибке после
  mutation; config topology не активируется policy неявно.
- API version и configuration schema version остаются равны 1.

## Completed

- Required `config=` contract используется обычными policies и
  `required_pam_enforcement`; missing/wrong/duplicate/malformed paths rejected.
- Добавлены typed `PasswdqcDirective`, `PasswdqcEffectiveState` и recursive
  evaluator с limits, loop/symlink/ownership/permissions validation.
- Все managed passwdqc postconditions проверяют effective state; native unknown
  и invalid directives fail before mutation.
- Добавлен `PamConfigFileTransaction` и fault-injection rollback tests, включая
  refusal перезаписать concurrent external change.
- Grammar удалена из platform capability и определяется provider descriptor.
- Generated PAM defaults выбираются по quality/history providers; synthetic
  passwdqc+pwhistory и pwquality-without-history compositions покрыты tests.
- Реальный read-only PAM graph ALT Workstation 11.2/p11 подтверждён на
  `10.88.0.86`: passwd → system-auth → system-auth-local-only →
  `pam_passwdqc.so config=/etc/passwdqc.conf`.

## Changed areas

- `fic/src/modules/identity_access/pam/`, passwdqc policies.
- `fic/src/platform/`, PAM platform profiles.
- `cmake/FicTargetPlatform.cmake`, `cmake/FicPamPolicyDefaults.cmake`,
  generated IDENTITY_ACCESS defaults path.
- PAM/platform unit tests, static checks и architecture documentation.

## Validation

- Target `fic` успешно собран для всех пяти profiles: Debian 12/13,
  Ubuntu 24.04/26.04, ALT p11.
- На каждом profile успешно прошли 8 tests:
  `platform_profile_static_checks`, `pam_packaging_static_checks`,
  `pam_configuration_tests`, `passwdqc_config_file_tests`,
  `alt_pam_faillock_topology_tests`, `identity_policy_hierarchy_tests`,
  `platform_profile_tests`, `pam_policy_defaults_tests`.
- Read-only runtime topology/package inspection ALT p11 выполнен; system PAM не
  изменялся.
- Full Ubuntu build запущен: `fic`, `fic-cli` и affected targets собраны, общий
  build остановился на отсутствующем dependency header `systemd/sd-login.h` у
  `fic-session-agent`.
- Full Ubuntu CTest: 50 passed, 4 skipped environment-dependent, 1 unrelated
  `ipc_protocol_validation_tests` failed из-за старого ожидания, что валидный
  `api_version: 1` должен отклоняться.

## Remaining

- Live weak/strong password и FIC policy apply не выполнялись: текущие binaries
  не устанавливались на disposable ALT userspace, host PAM не изменялся.
- Для полного build требуется development header `systemd/sd-login.h`;
  unrelated `ipc_protocol_validation_tests` не исправлялся в PAM scope.
