# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущего task commit:
  `377e669626e2ae6b566d569d2e5be1197a80f04f`.

## Current task

- Исправлен NSS proof policy `disable_nopasswdlogin` для штатной ALT p11
  topology `passwd: files systemd`, `group: files systemd role`.

## Accepted architecture / invariants

- `ExplicitPasswordlessLogin` описывает понятую platform-specific PAM-ветку,
  но не утверждает, что на ней был выполнен `pam_faillock`.
- ALT rule доверяется только при exact service/module/simple control/ordered
  arguments/source; generic analyzer не содержит ALT-specific исключений.
- `disable_nopasswdlogin` не редактирует package-owned PAM-файлы. Typed ALT
  contract разрешает только exact поддержанные последовательности `files`,
  `systemd`, `role`; remote/unknown services и NSS action overrides отклоняются.
- Mutation ограничена local `/etc/group` через verified `gpasswd`. Security
  postcondition вычисляется через libc NSS: primary GID, `gr_mem` и
  `getgrouplist`, то есть соответствует `pam_succeed_if user ingroup`.
- Отсутствующая `initgroups:` использует glibc fallback к `group:`. Остаточная
  effective membership, включая `libnss-role`, завершается fail-closed.
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
- Удалён параллельный parser `nsswitch.conf`: policy использует существующий
  `NssConfiguration`; добавлен injectable effective-membership resolver.
- Regression покрывает реальную ALT topology, systemd-only, supported/absent/
  remote initgroups, role residual, primary GID, gpasswd failure и повторный
  apply.

## Changed areas

- ALT/platform PAM profile and typed NSS compatibility contract.
- PAM control-flow analyzer and identity policy dependency metadata.
- `PamDisableNopasswdloginPolicy`, libc/NSS resolver, daemon registration and
  resources.
- PAM/platform/identity tests and user-facing documentation.

## Validation

- Собраны `fic` и изменённые PAM/platform/identity/planner test targets.
- Relevant CTest: 18/18 passed.
- Полный доступный CTest: 53 passed, 4 штатно skipped, 0 failed из 57.
- `platform_profile_tests` passed для ALT p11, Debian 12/13 и Ubuntu 24.04/26.04.
- Полная сборка останавливается на незатронутом `fic-session-agent`: в
  окружении отсутствует `systemd/sd-login.h`.
- `git diff --check` passed.
- Read-only `10.88.0.86`: подтверждены `files systemd` / `files systemd role`,
  отсутствие отдельной `initgroups:`, `nopasswdlogin: ABSENT`, exact GDM rule и
  пакеты pam 1.7.1, libnss-systemd 257.9, libnss-role 0.5.6.

## Remaining

- Новая сборка не устанавливалась на `10.88.0.86`; фактический вызов новой
  policy там не выполнялся. Текущее read-only состояние соответствует её
  Applied/no-op ветке, поскольку effective NSS group отсутствует.
- Host-impact absent/empty/supplementary/primary/role runtime cases проверять
  только в согласованном staging/одноразовом окружении.
