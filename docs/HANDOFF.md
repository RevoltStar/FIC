# FIC: передача контекста

## Current base

- Ветка: `main`.
- HEAD до текущих незакоммиченных изменений:
  `81001cca5cb2d924d745a8c4ea103191b094cd64`.

## Current task

- Исправлена FIC-managed `pam_faillock` topology на ALT p11 для штатного
  split graph: SSH authentication идёт через
  `system-auth-use_first_pass-local-only`, а account — через
  `system-auth-local-only`.

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
- `pam_faillock` и `pam_pwhistory` используют независимые markers и должны
  безопасно сосуществовать в общем primary target.

## Completed

- В platform profile добавлены два typed ALT p11 targets и строгая validation
  их путей, уникальности и ролей.
- `AltPamFaillockTopologyManager` переведён на multi-target preflight,
  mutation, verification и rollback.
- Semantic postcondition проверяет primary local stack и configured services,
  реально использующие дополнительный authentication target, включая штатный
  `sshd` graph.
- Реалистичный SSH regression fixture больше не подменяет
  `system-auth-use_first_pass-local-only` обычным local-only файлом.
- Добавлены negative, idempotence, multi-target rollback и
  faillock/pwhistory coexistence tests.
- Обновлено описание ALT RPM/runtime contract.

## Changed areas

- `fic/src/platform/` и ALT p11 profile.
- `fic/src/modules/identity_access/pam/AltPamFaillockTopologyManager.cpp`.
- ALT PAM topology/platform tests.
- `fic/README.md`, `packaging/rpm/README.md`,
  `docs/architecture-diagrams.md`.

## Validation

- Успешно собраны targets: `fic`, `alt_pam_faillock_topology_tests`,
  `alt_pam_password_history_topology_tests`, `pam_configuration_tests`,
  `identity_configuration_transaction_tests`,
  `identity_policy_hierarchy_tests`, `identity_configuration_editors_tests`,
  `identity_concrete_policies_tests`, `platform_profile_tests`.
- Passed 11/11 relevant CTest: platform/static/packaging, PAM topology and
  configuration, identity policy/configuration и defaults tests.
- Полная сборка `cmake --build build-hardening-altp11 -j2` остановилась на
  незатронутом `fic-session-agent`: в окружении отсутствует
  `systemd/sd-login.h`.
- `git diff --check` passed.

## Remaining

- Исправленная сборка не развёртывалась на `10.88.0.86`; runtime-повтор
  `control fic-pam-faillock enabled` требует сборки и установки нового RPM.
