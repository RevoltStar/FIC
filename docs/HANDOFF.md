# FIC: передача контекста

## Current base

- Ветка `main`, исходная база текущей правки:
  `febab29cc7a4797cc084450c21140a56dac5873d`.

## Current task

- Реализован первый production `DesktopSystemBackend` для GNOME и
  `OSS/DesktopEnvironment/screenlock_timeout` переведён для controlled GNOME в
  `MandatoryGlobal`.

## Accepted architecture / invariants

- `GnomeSystemBackend` (`backendName() == "gnome"`, typed desktop `Gnome`) —
  единственный global enforcement path для GNOME.
- FIC использует `/etc/dconf/profile/user`, отдельную compiled database
  `/etc/dconf/db/fic`, keyfile `/etc/dconf/db/fic.d/99-fic.conf` и locks
  `/etc/dconf/db/fic.d/locks/99-fic`.
- `system-db:fic` размещается сразу после первой writable database; foreign
  profile lines и их относительный порядок сохраняются. Malformed profile и
  duplicate `system-db:fic` отклоняются до mutation.
- FIC keyfile и lock file обновляются merge-only; `DISABLE` не удаляет старые
  FIC values/locks. Cleanup, rollback и provenance вне scope.
- Directory traversal и file replacement выполняются через `openat` с
  `O_NOFOLLOW`, проверкой owner/type/mode и atomic same-directory rename/fsync.
- `dconf update` и `gsettings` запускаются без shell через optional
  `ExecutableId::Dconf`/`Gsettings`, resolver и `VerifiedProcessExecutor`.
- Effective verification требует exact `gsettings get` и
  `gsettings writable == false` по explicit clean `DCONF_PROFILE` для всех
  трёх keys. Stale compiled state получает одну bounded recompilation attempt.
- `screenlock_timeout`: GNOME — `MandatoryGlobal`; KDE/XFCE/FLY —
  `SessionOnly`; LXQt — `Unsupported`. Current GNOME session convergence
  сохраняется как best effort после global verification.

## Completed / changed areas

- Добавлены `GnomeSystemBackend.{h,cpp}`, production registration и hardened
  dconf profile/keyfile/locks lifecycle.
- `OSS_screenlock_timeout` публикует три canonical GNOME requirements и
  независимо читает configured timeout для Stage A.
- Platform profiles получили optional `dconf`/`gsettings` executable IDs.
- Добавлены backend unit tests, actual-policy/reconciler integration tests,
  platform/static contract checks и обновлена DE architecture documentation.

## Validation

- Fresh configure `/tmp/fic-gnome-system-check`, target platform
  `ubuntu-24.04` — passed.
- Full build — passed.
- Targeted DE/platform набор: 12/12 passed.
- Full CTest: 82 tests, 81 passed, 1 root-only skipped, 0 failed.
- Реальный dconf 0.40: `99-fic.conf` и extensionless basename дали identical
  compiled DB; `dconf update <temporary-db-dir>` создал compiled `fic`.
- Реальные `gsettings get`/`writable` с absolute `DCONF_PROFILE` выполнены
  read-only; live GNOME session не проверялась.
- Negative controls: wrong value и writable key отвергаются unit tests;
  временный возврат GNOME в `SessionOnly` сломал policy regression test, после
  восстановления test passed.

## Remaining

- Live GNOME session/runtime integration не проверялась: доступной disposable
  GNOME session нет.
- Root-only `command_hash_batch_tests` skipped.
