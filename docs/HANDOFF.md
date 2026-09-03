# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей незакоммиченной правки:
  `6cc52b186412bd357ee8cff146ad86bd3c0d5209`.

## Current task

- Исправлен false `failure_accounting_bypass` анализатора PAM на штатном ALT
  p11 GDM graph с `pam_tcb.so` и `pam_gnome_keyring.so`.

## Accepted architecture / invariants

- Exact trusted bypass `gdm-password` / `pam_succeed_if.so user ingroup
  nopasswdlogin`, `ExplicitPasswordlessLogin`, NSS contract, Recommended
  dependencies и topology managers не изменялись.
- Return codes моделируются отдельно по PAM module и management group;
  невозможный результат не переосмысливается как успешная аутентификация.
- `pam_gnome_keyring.so` — известный auxiliary consumer `PAM_AUTHTOK`; его
  auth result не является evidence первичной проверки credentials.
- Generic control-action/evidence semantics осталась fail-closed и не получила
  blanket-исключения для `action=ignore`.

## Completed

- По ALT `tcb-1.2-alt2` подтверждено: `pam_sm_authenticate()` не возвращает
  `PAM_NEW_AUTHTOK_REQD`; этот code формируется account entry point для
  истёкшего пароля.
- Для `pam_tcb.so` добавлены отдельные точные Auth/Account outcome contracts.
- Для `pam_gnome_keyring.so` добавлены Auth outcomes и роль `Auxiliary`.
- Добавлен positive regression на реальный ALT GDM graph и negative regression
  на настоящий `pam_tcb PAM_AUTH_ERR`, обходящий `pam_faillock authfail`.
- Собран ALT p11 RPM и установлен daemon package на `10.88.0.86`; перед
  установкой создан `/var/tmp/fic-pam-analyzer-backup-20260903-1.tar.gz`.
- Runtime apply: `total=30, applied=20, failed=0, disabled=10`; все четыре
  `failed_authentication_*` и `required_pam_enforcement` применились.

## Changed areas

- `PamControlFlowAnalyzer.cpp`.
- `PamConfigurationTests.cpp`.
- Этот HANDOFF.

## Validation

- Собраны `fic` и все relevant PAM/platform/planner targets.
- Relevant CTest: 7/7 passed.
- Полный доступный CTest: 53 passed, 4 штатно skipped, 0 failed из 57.
- Локальная full build остановилась на отсутствующем `systemd/sd-login.h` в
  host environment; полная ALT p11 container/RPM build завершилась успешно.
- На host SHA-256 `/opt/fic/bin/fic` совпал с daemon из RPM; daemon active,
  свежий SSH login успешен, post-restart journal без warning/error.
- `control fic-pam-faillock status` и `control fic-pam-pwhistory status`:
  `enabled`.

## Remaining

- Изменения не коммитить без явной команды пользователя.
- На текущем host `disable_nopasswdlogin` оказался enabled/applied, поэтому
  disabled Recommended-dependency WARN в этом runtime запуске не наблюдался.
- ALT `rpm --replacepkgs` сообщил `erase failed` при cleanup старой копии того
  же NEVRA, но RPMDB содержит одну запись, установленный binary совпадает с
  новым RPM и daemon успешно перезапущен.
