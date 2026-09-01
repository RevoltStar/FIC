# FIC: передача контекста

## Current base

- Ветка: `main`.
- HEAD до текущих незакоммиченных изменений:
  `55499fee6847f3750907e3579d3476d7b780372b`.

## Current task

- Исправлен false positive semantic verification штатного ALT p11 SSH graph:
  operational error `pam_faillock preauth`, завершающий stack fail-closed,
  больше не выдаётся за `failure_accounting_bypass` после `pam_userpass`.

## Accepted architecture / invariants

- ALT lockout capability задаёт typed managed targets с ролями, а manager не
  выводит второй путь строковой заменой.
- `system-auth-local-only` владеет authentication+account blocks;
  `system-auth-use_first_pass-local-only` владеет authentication blocks и
  сохраняет штатные аргументы `pam_tcb`, включая `use_first_pass`.
- Все targets проверяются до первой записи, изменяются под одним lock и
  откатываются до exact original bytes при write/postcondition failure.
- `PamProviderInspector` и глобальная semantics
  `required_pam_enforcement` не ослаблены.
- Credential failure, завершившийся до достижения `pam_faillock`, остаётся
  настоящим `failure_accounting_bypass`; исключение относится только к
  fail-closed результату самого `preauth`.
- `pam_faillock` и `pam_pwhistory` используют независимые markers и должны
  безопасно сосуществовать в общем primary target.

## Completed

- Реалистичный SSH fixture дополнен фактическими `pam_userpass`,
  `pam_nologin`, `system-auth-common` и полным `common-login` graph.
- В control-flow evidence добавлено различение fail-closed operational result
  `pam_faillock preauth` и credential failure до provider.
- Добавлен негативный тест, сохраняющий обнаружение настоящего раннего bypass.
- Обновлено описание semantic verification ALT RPM/runtime contract.

## Changed areas

- `fic/src/modules/identity_access/pam/PamControlFlowAnalyzer.cpp`.
- PAM configuration и ALT topology tests.
- `fic/README.md`, `packaging/rpm/README.md`,
  `docs/architecture-diagrams.md`.

## Validation

- Успешно собраны targets: `fic`, `alt_pam_faillock_topology_tests`,
  `alt_pam_password_history_topology_tests`, `pam_configuration_tests`,
  `identity_policy_hierarchy_tests`, `platform_profile_tests`.
- Passed 11/11 relevant CTest: platform/static/packaging, PAM topology and
  configuration, identity policy/configuration и defaults tests.
- Полная сборка `cmake --build build-hardening-altp11 -j2` остановилась на
  незатронутом `fic-session-agent`: в окружении отсутствует
  `systemd/sd-login.h`.
- `git diff --check` passed.

## Remaining

- Текущая analyzer-правка не развёртывалась на `10.88.0.86`; runtime-повтор
  `control fic-pam-faillock enabled` требует сборки и установки нового RPM.
