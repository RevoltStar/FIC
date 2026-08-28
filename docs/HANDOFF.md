# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `721091f67ff97ba18f9d74f424a194db9de6295f`.
- Реализация: `ef483fa` (`PAM переведён на capability-oriented архитектуру с native passwdqc`).

## Current task

- Capability/provider/config grammar/topology/platform composition refactor PAM
  с native passwdqc backend для ALT p11.

## Accepted architecture / invariants

- Цепочка PAM: logical policy → capability → provider backend → typed
  config grammar → topology strategy → platform composition.
- Generic policy code не ветвится по distro; platform profile декларативно
  задаёт provider, scope, config path и topology strategy для каждой capability.
- Registry публикует только policy features с реальным mapping выбранного
  provider. Configuration mutation не активирует PAM topology неявно.
- Passwdqc использует strict native `option=value`, PAM argument `config=` и
  typed five-field `min`; pwquality-only semantics на него не переносятся.
- API version и configuration schema version остаются равны 1.

## Completed

- Добавлены capability/scope/provider/grammar/topology/support descriptors и
  общие `PamPlatformComposition`, `PamProviderCatalog`, `PamTopologyManager`.
- Debian 12/13 и Ubuntu 24.04/26.04 переведены на pwquality/pwhistory/faillock
  composition с external opt-in topology.
- ALT p11 переведён на native passwdqc + ALT/tcb managed faillock; password
  history на ALT явно unsupported.
- Добавлены strict passwdqc parser/writer, typed codecs, native policies,
  provider-specific root enforcement mapping и capability-aware registry.
- Сохранены atomic write, ownership checks, rollback/postcondition и safe ALT
  topology semantics; обновлены platform-generated defaults и локализация.
- Обновлена архитектурная, daemon и packaging documentation.

## Changed areas

- `fic/src/platform/` и все пять platform profiles.
- `fic/src/modules/identity_access/pam/`, PAM policies и registry initialization.
- `fic/src/resources/config/IDENTITY_ACCESS.conf.in`, `ru.lang`, `en.lang`.
- PAM/platform tests и static checks.
- `fic/README.md`, `docs/architecture-diagrams.md`, packaging README.

## Validation

- Target `fic` успешно собран для `debian-12`, `debian-13`, `ubuntu-24.04`,
  `ubuntu-26.04` и `alt-p11`.
- На каждом из пяти profiles успешно прошли 7 tests:
  `platform_profile_static_checks`, `pam_packaging_static_checks`,
  `pam_configuration_tests`, `passwdqc_config_file_tests`,
  `alt_pam_faillock_topology_tests`, `identity_policy_hierarchy_tests`,
  `platform_profile_tests`.
- Дополнительные targeted tests CLI/session/desktop/device/user creation прошли;
  существующий `ipc_protocol_validation_tests` вне PAM падает из-за
  противоречивого ожидания, что корректный `api_version: 1` unsupported.
- Full Ubuntu build запускался и остановился на отсутствующем dependency header
  `systemd/sd-login.h` у `fic-session-agent`; `fic` и PAM targets собираются.
- Live PAM apply и behavioral tests с disposable users не запускались.

## Remaining

- Выполнить full build/CTest в target userspace с development headers systemd.
- При наличии disposable ALT/Debian userspace добавить behavioral PAM tests:
  weak/strong password, lockout/unlock и password history reuse.
- Известный unrelated дефект `ipc_protocol_validation_tests` не исправлялся в
  PAM-задаче.
