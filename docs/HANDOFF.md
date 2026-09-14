# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `856f62509fcee34b5cd4b1b10bd1aac740615df7`.
- Рабочее дерево содержит незакоммиченную текущую PAM-правку.

## Current task

- Безопасная поддержка штатного ALT p11 FreeIPA/SSSD PAM/NSS layout без
  распространения локальных `pam_faillock`/`passwdqc` policies на domain users.

## Accepted architecture / invariants

- ALT trusted aliases разрешают только перечисленные exact `system-auth-*`
  targets, включая штатные `*-sss`; произвольные targets остаются fail-closed.
- ALT `AuthenticationLockout` и `PasswordQuality` имеют typed
  `LocalUsersOnly` semantics. CFG различает local/non-local paths по
  `pam_localuser`; неизвестный subject остаётся в fail-closed анализе.
- `PasswordQuality` проверяет только `system-auth-local-only`; SSS password
  branch не обязана содержать `pam_passwdqc`.
- При NSS `sss` policy `disable_nopasswdlogin` не использует enumeration, а
  атомарно удаляет exact typed GDM/LightDM PAM bypass rules с postcondition и
  exact rollback. Локальный NSS сохраняет group-membership enforcement.

## Completed

- Добавлены exact ALT SSS aliases и local-only capability metadata.
- CFG analyzer моделирует subject identity и принимает штатный hybrid router,
  сохраняя обязательность `pam_faillock` на local branch.
- Реализован SSS-safe PAM enforcement для `disable_nopasswdlogin`.
- Добавлены regressions для aliases, router, local `passwdqc`, SSS без
  enumeration, exact/non-exact rules, idempotency и rollback.
- Обновлены относящиеся к контракту README, architecture docs и policy text.

## Changed areas

- `fic/src/platform/`
- `fic/src/modules/identity_access/pam/`
- PAM/platform tests и `tests/CMakeLists.txt`
- `fic/README.md`, `docs/architecture-diagrams.md`, policy localization

## Validation

- ALT configure в `build-alt-sss` — passed ранее с configure-only
  `libsystemd.pc` shim.
- Targeted build: `pam_configuration_tests`,
  `pam_control_flow_analyzer_tests`, `pam_disable_nopasswdlogin_policy_tests`,
  `alt_pam_faillock_topology_tests`, `platform_profile_tests` — passed.
- Targeted CTest: 7/7 passed, включая два relevant static checks.
- Additional PAM CTest: 3/3 passed (`pam_capability_activation_policy_tests`,
  `passwdqc_config_file_tests`, `pam_policy_defaults_tests`).
- `python3 tests/fic/platform/static_checks.py .` — passed.
- `python3 tests/common/static_checks.py .` — passed.
- Production target `fic` запущен, но окружение не содержит
  `systemd/sd-daemon.h`; сборка остановилась на `fic/src/main.cpp` до link.
- `git diff --check` — passed.

## Remaining

- Изменения не закоммичены.
- Полная сборка и полный CTest не запускались.
