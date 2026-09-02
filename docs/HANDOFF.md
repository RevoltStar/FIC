# FIC: передача контекста

## Current base

- Ветка: `main`.
- HEAD до текущих незакоммиченных изменений:
  `377e669626e2ae6b566d569d2e5be1197a80f04f`.

## Current task

- Реализован exact typed trusted bypass штатной ALT p11 GDM-ветки
  `pam_succeed_if` и отдельная policy `disable_nopasswdlogin`.

## Accepted architecture / invariants

- `ExplicitPasswordlessLogin` описывает понятую platform-specific PAM-ветку,
  но не утверждает, что на ней был выполнен `pam_faillock`.
- ALT rule доверяется только при exact service/module/simple control/ordered
  arguments/source; generic analyzer не содержит ALT-specific исключений.
- `disable_nopasswdlogin` не редактирует package-owned PAM-файлы. Она требует
  files-only NSS для `passwd`, `group` и объявленного `initgroups`, очищает
  supplementary members через verified `gpasswd`, а primary GID и внешний NSS
  отклоняет fail-closed.
- Policy является только Recommended dependency authentication/lockout
  policies; password quality/history policies от неё не зависят.

## Completed

- Regression сначала воспроизвёл исходный `authentication_bypass` на реальном
  `gdm-password -> common-login` fixture.
- Расширены typed platform metadata и analyzer acceptance evidence для
  `ExplicitPasswordlessLogin`.
- Добавлены policy, registration, config defaults, RU/EN resources и
  `Gpasswd` executable metadata.
- Добавлены Recommended dependencies для четырёх `failed_authentication_*`
  policies и `required_pam_enforcement` только на поддерживающей платформе.
- Добавлены positive/negative analyzer, enforcement, NSS, postcondition и
  dependency tests; обновлены README, RPM и architecture docs.

## Changed areas

- ALT/platform PAM profile and compatibility contracts.
- PAM control-flow analyzer and identity policy dependency metadata.
- `PamDisableNopasswdloginPolicy`, daemon registration and resources.
- PAM/platform/identity tests and user-facing documentation.

## Validation

- Собраны `fic` и все изменённые PAM/platform/identity/planner test targets.
- Relevant CTest: 15/15 passed.
- Полный доступный CTest: 53 passed, 4 штатно skipped, 0 failed из 57.
- `platform_profile_tests` passed для ALT p11, Debian 12/13 и Ubuntu 24.04/26.04.
- Полная сборка останавливается на незатронутом `fic-session-agent`: в
  окружении отсутствует `systemd/sd-login.h`.
- `git diff --check` passed.

## Remaining

- Изменения не закоммичены по прямому указанию пользователя.
- Новая сборка не устанавливалась на `10.88.0.86`. Нужна runtime-проверка на
  реальном ALT p11: exact GDM graph, `disable_nopasswdlogin` для тестовых
  absent/empty/supplementary/primary/NSS случаев и повторный apply lockout
  policies. Host-impact PAM проверки выполнять только в согласованном
  staging/одноразовом окружении.
