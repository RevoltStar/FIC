# FIC: передача контекста

## Current base

- Ветка: `main`.
- HEAD до текущих незакоммиченных изменений: `9b6707a`.

## Current task

- Исправлены fail-open symlink PAM service sources и legacy
  `pam_pwhistory` semantics Debian 12/Linux-PAM 1.5.2.

## Accepted architecture / invariants

- `PamCapabilityConfigurationMode` выбирает `ProviderConfigFile` либо
  `ModuleArguments`; policy layer не ветвится по distro/version.
- Debian 12 PasswordHistory выбирает `ModuleArguments`; Debian 13 и Ubuntu
  сохраняют `pwhistory.conf`; ALT p11 не объявляет capability.
- `PamProviderModuleArguments` является generic strategy boundary, а
  `PamPwhistoryArguments` реализует case-insensitive legacy native grammar.
- Legacy mutation изменяет только однозначный parsed `pam_pwhistory.so` rule,
  сохраняет `use_authtok` и разрешённые argv, использует atomic snapshot,
  reread/reparse/effective-graph postcondition и rollback.
- PAM service sources открываются через `O_NOFOLLOW|O_CLOEXEC`, читаются из
  проверенного regular-file fd; top-level и included symlink fail closed.

## Completed

- Legacy `remember=N` и `enforce_for_root` mutation/verification реализованы
  без использования или создания `/etc/security/pwhistory.conf` на Debian 12.
- Required PAM в legacy mode проверяет фактические argv и считает
  `remember=0` ineffective.
- Добавлены production-path regressions: initial/change/idempotent depth,
  enable/disable flag, argv preservation, invalid/duplicate argv/provider,
  malformed source, include cycle, symlink sources, ignored config file и
  postcondition rollback.
- Обновлены profile validation, localization и PAM/package architecture docs.

## Changed areas

- `fic/src/modules/identity_access/pam/`.
- PAM platform metadata и Debian 12 profile.
- PAM hierarchy/profile tests, localization и PAM documentation.

## Validation

- Target `fic` собран для Debian 12/13, Ubuntu 24.04/26.04 и ALT p11.
- На каждом из пяти profiles прошли 8/8 targeted PAM/profile tests.
- Полный Debian 12 CTest: 49 passed, 4 skipped, 2 unrelated failed из 55.
  `path_layout_static_checks` видит существующие ignored obsolete directories;
  `ipc_protocol_validation_tests` падает на существующем IPC assertion. PAM
  tests в полном прогоне прошли.
- Configure использовал pkg-config stub для отсутствующего `libsystemd-dev`;
  daemon и все test executables собраны, `fic-session-agent` не собирался.
- `git diff --check` пройден.

## Remaining

- Live PAM E2E (`live_pwhistory`, topology activation/roundtrip и service
  symlink fixture) не запускались: host PAM не изменялся.
- Полная сборка всех product executables не выполнена из-за отсутствующего
  `libsystemd-dev`.
- Два unrelated full-CTest failure требуют отдельной задачи, если они ещё
  актуальны в чистом checkout.
