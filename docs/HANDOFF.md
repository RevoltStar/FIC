# FIC: передача контекста

## Current base

- Ветка: `main`.
- HEAD до текущих незакоммиченных изменений:
  `340329c9a0119660a18415a0e0eebc3c11da90a0`.

## Current task

- Добавлена безопасная поддержка `pam_pwhistory` для ALT Linux p11 с TCB без
  отдельного RPM-пакета.

## Accepted architecture / invariants

- `fic` RPM содержит `pam_fic_pwtxn.so`, выделенный
  `/etc/security/fic-pwhistory.conf` и native control facility
  `fic-pam-pwhistory`; topology активируется администратором явно.
- Общий `/var/lib/fic-pwhistory/opasswd` защищён lock, охватывающим
  `pam_pwhistory` и последующую запись `pam_tcb`.
- Storage directory имеет `root:shadow 2730`; `opasswd` и `.lock` — regular
  one-link `root:shadow 0660`. Lock path зафиксирован в PAM-модуле.
- Пакетный config содержит `remember=0`, поэтому установка и topology
  activation не включают history enforcement до применения policy.
- `/etc/security/fic-pwhistory.conf` упакован как `%config(noreplace)`; working
  policy configs под `/opt/fic/config` по-прежнему не являются RPM configs.
- Хостовый PAM не изменялся; runtime-проверки выполнялись только в Podman.

## Completed

- ALT profile объявляет `PasswordHistory/PamPwhistory` и включает provider в
  generated `required_pam_enforcement` default.
- Добавлены PAM transaction module, ALT topology manager с atomic rollback,
  secure storage preparation, проверкой effective include stack и maintenance
  command `pam-alt-pwhistory`.
- RPM устанавливает control facility/module/config, сохраняет facility state
  при upgrade, готовит storage и fail-closed отключает topology при final erase.
- Platform feature flag управляет сборкой/install transaction module без
  literal distribution id в `fic/CMakeLists.txt`.
- Обновлены manager/platform/policy/packaging tests и документация.

## Changed areas

- `fic/src/modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.*`.
- `fic/src/pam-modules/`, `fic/src/resources/pam/`, ALT platform/CMake/main.
- `packaging/rpm/` build dependency, lifecycle, facility и документация.
- PAM/platform/policy/static contract tests и `fic/README.md`.

## Validation

- Affected ALT targets собраны: `fic`, `pam_fic_pwtxn`, topology/platform/policy
  tests.
- Targeted CTest: 10/10 passed, включая оба relevant static contract tests,
  новый topology manager test и существующий PAM/platform/policy suite.
- `pam_fic_pwtxn.c` отдельно собран с `-Wall -Wextra -Werror`.
- Штатная Podman RPM-сборка `0.0.0-pwhistory` создала все пять ALT packages;
  `fic-pwhistory.conf` подтверждён как RPM config+noreplace (flags `17`).
- Packaged ALT p11 runtime test в отдельном Podman storage passed: install,
  disabled default, idempotent enable, `remember=0`, concurrent ordinary-user
  SGID `passwd`, reuse rejection без TCB mutation, cleanup unlock и точный
  disable round-trip.
- `bash -n`, `sh -n` и `git diff --check` passed.
- Полный host build не завершён: в текущем окружении отсутствует development
  header `systemd/sd-login.h` для `fic-session-agent`. Все package components
  при этом успешно собраны штатной ALT Podman RPM-сборкой.

## Remaining

- Незавершённой работы в текущем scope нет.
