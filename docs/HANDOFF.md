# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `9891276`.
- Рабочее дерево содержит незакоммиченную текущую PAM-правку.

## Current task

- Убрать небезопасную стратегию `authsucc` из advertised capabilities ALT p11
  и закрепить CFG regression для внешнего отказа после возврата из
  `system-auth-use_first_pass`.

## Accepted architecture / invariants

- ALT p11 поддерживает для `enable_authentication_lockout` только
  `preauth_required` и `preauth_requisite`; default остаётся
  `preauth_required`.
- `authsucc` внутри ALT `system-auth*` небезопасен: внешний service-level gate
  может завершить аутентификацию отказом уже после сброса tally.
- Общий CFG analyzer и поддержка `authsucc` для Debian/Ubuntu не ослабляются.

## Completed

- `Authsucc` удалён из `supportedFaillockStrategies` профиля ALT p11.
- Platform-profile test проверяет exact ALT strategy set.
- Добавлен analyzer regression с цепочкой
  `sshd -> common-login-use_first_pass -> system-auth-use_first_pass ->
  pam_nologin`, ожидающий `PrematureSuccessAccounting`.
- README уточняет платформенные различия стратегий.

## Changed areas

- `fic/src/platform/profiles/AltP11Profile.cpp`
- `tests/fic/platform/PlatformProfileTests.cpp`
- `tests/fic/modules/identity_access/pam/PamControlFlowAnalyzerTests.cpp`
- `fic/README.md`

## Validation

- ALT CMake configure с локальным configure-only `libsystemd.pc` shim — passed.
- Build targets `pam_control_flow_analyzer_tests`, `platform_profile_tests` —
  passed.
- Targeted CTest: 4/4 passed (`pam_control_flow_analyzer_tests`,
  `platform_profile_static_checks`, `pam_packaging_static_checks`,
  `pam_policy_defaults_tests`).
- Узкий executable против собранного `fic-platform` подтвердил exact ALT set
  `{PreauthRequired, PreauthRequisite}` и default `PreauthRequired` — passed.
- `python3 tests/fic/platform/static_checks.py .` — passed.
- `python3 tests/common/static_checks.py .` — passed.
- Общий `platform_profile_tests` проходит новую ALT assertion, затем падает на
  существующем несвязанном `/etc/resolv.conf` provider-target test helper,
  который не применим к ALT profile.

## Remaining

- Изменения не закоммичены.
- Полная сборка и полный CTest не запускались.
