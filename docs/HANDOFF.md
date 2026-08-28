# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `cce073e`.
- Реализация: `0173c24`..`6fb7004`.

## Current task

- Закрыты review-проблемы capability-oriented PAM: полная native-семантика
  passwdqc, snapshot-conditional config transaction, безопасные optional
  provider defaults и проверка согласованности generated defaults.

## Accepted architecture / invariants

- Effective passwdqc state вычисляется в native порядке: defaults, все PAM argv,
  рекурсивный `config=`, затем оставшиеся argv; любой неизвестный или невалидный
  аргумент отклоняется fail-closed.
- Structural verification допускает исправляемый `enforce=none` только до
  mutation; postcondition и `required_pam_enforcement` требуют security-effective
  state.
- `PamConfigFileTransaction` — единственный владелец conditional commit и
  rollback. Commit сверяет captured identity/content/metadata непосредственно
  перед заменой, отсутствующий target создаётся exclusive, rollback разрешён
  только для точно распознанного committed output.
- Optional external config path берётся из provider descriptor. Явный path
  обязан совпадать с managed path; отсутствие аргумента допустимо только для
  native default path.
- CMake provider selection и active platform composition пока остаются двумя
  representations, но их расхождение блокируется direct profile test.

## Completed

- Passwdqc verifier использует один recursive evaluator для PAM argv и config
  files, проверяет все invocations/services и cross-option semantics, включая
  `random=N,only` и финальный `enforce=none`.
- Устранено capture-to-mutation окно: atomic writer получил expected target
  state, transaction state machine и ownership-aware rollback; вложенные
  rollback-механизмы удалены.
- Для `pam_faillock`, `pam_pwquality` и `pam_pwhistory` зафиксированы native
  default paths; generic inspector не содержит provider-specific ветвлений.
- Добавлены regression/fault-injection tests для argv ordering, invalid state,
  нескольких services, replacement/in-place/metadata races, missing-target race
  и отказа rollback поверх внешнего изменения.
- Добавлен cross-profile consistency gate generated PAM defaults.

## Changed areas

- `fic-common/fic-core` atomic file writer.
- `fic/src/modules/identity_access/pam/` и passwdqc policies.
- PAM provider metadata и platform/CMake composition selection.
- PAM, transaction, topology и platform profile tests.

## Validation

- Target `fic` успешно собран для Debian 12/13, Ubuntu 24.04/26.04 и ALT p11.
- На каждом из пяти profiles успешно прошли 8 tests:
  `platform_profile_static_checks`, `pam_packaging_static_checks`,
  `pam_configuration_tests`, `passwdqc_config_file_tests`,
  `alt_pam_faillock_topology_tests`, `identity_policy_hierarchy_tests`,
  `platform_profile_tests`, `pam_policy_defaults_tests`.
- Configure использовал только pkg-config stub для отсутствующего на host
  `libsystemd`; `fic-session-agent` этой матрицей не собирался.
- `git diff --check` пройден; stale transaction/verifier API поиском не найден.

## Remaining

- Live weak/strong password и FIC policy apply не выполнялись: доступного
  disposable ALT окружения с текущими binaries нет, host PAM не изменялся.
- Полная сборка всех executable и полный CTest в этой задаче не запускались;
  проверены daemon и непосредственно затронутые tests на всех profiles.
- Generated defaults не сведены к единственному runtime representation: выбран
  допустимый review fallback с обязательной test-time consistency assertion.
