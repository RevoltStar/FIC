# FIC: передача контекста

## Current base

- Ветка: `main`.
- HEAD до текущих незакоммиченных изменений:
  `340329c9a0119660a18415a0e0eebc3c11da90a0`.

## Current task

- Исправлена активация FIC-managed `pam_faillock` topology на ALT p11, где
  штатный SSH PAM graph проходит через selector
  `/etc/pam.d/system-auth-use_first_pass`.

## Accepted architecture / invariants

- PAM service symlink остаются запрещены по умолчанию; ALT profile разрешает
  только точные package-owned selectors и их явные allowlist targets.
- `control system-auth` переключает согласованную пару selectors:
  `system-auth` и `system-auth-use_first_pass`; FIC должен безопасно разрешать
  оба при анализе effective authentication graph.
- Ошибка чтения/разрешения PAM graph не является доказательством внешней
  `pam_faillock` topology и диагностируется отдельно.
- `pam_faillock` topology по-прежнему активируется администратором явно через
  `control fic-pam-faillock enabled`.

## Completed

- В ALT p11 profile добавлен exact allowlist для
  `system-auth-use_first_pass-{local,ldap,krb5,krb5_ccreds,winbind,multi,pkcs11}`.
- Проверка relevant PAM graph различает `Clear`, подтверждённую external
  topology и ошибку инспекции; неизвестный symlink больше не выдаётся за
  найденный внешний `pam_faillock`.
- Добавлены regression-тест фактической цепочки
  `sshd -> common-login-use_first_pass -> system-auth-use_first_pass` и
  негативный тест неизвестного alias без PAM mutation.

## Changed areas

- `fic/src/platform/profiles/AltP11Profile.cpp`.
- `fic/src/modules/identity_access/pam/AltPamFaillockTopologyManager.cpp`.
- ALT topology/platform tests.

## Validation

- Собраны targets `alt_pam_faillock_topology_tests`,
  `platform_profile_tests`, `fic` в `build-hardening-altp11`.
- Passed 4/4:
  `platform_profile_static_checks`, `pam_configuration_tests`,
  `alt_pam_faillock_topology_tests`, `platform_profile_tests`.
- `git diff --check` passed после обновления HANDOFF.

## Remaining

- Исправленная сборка не развёртывалась на `10.88.0.86`; runtime-повтор
  `control fic-pam-faillock enabled` требует сборки/установки нового RPM.
