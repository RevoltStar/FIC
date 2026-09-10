# FIC: передача контекста

## Current base

- Ветка `main`.
- База до текущей незакоммиченной правки:
  `ceee93d7f0c0e3bebf391c5b0904d9e1ecad8399`.

## Current task

- Усилить KDE MandatoryGlobal screen-lock enforcement против FullConfig
  override из `kdedefaults/kdeglobals` и platform `XDG_CONFIG_DIRS`.

## Accepted architecture / invariants

- `KdeSystemBackend` merge-защищает одни и те же пять `[Daemon]` keys с
  per-key `[$i]` одновременно в `/etc/xdg/kscreenlockerrc` и
  `/etc/xdg/kdeglobals`.
- Оба файла и managed-синтаксис проверяются до первой записи; unrelated state
  сохраняется, `DISABLE` не выполняет cleanup.
- Effective proof выполняет один optional verified
  `/opt/fic/bin/fic-kconfig-verifier`, связанный с реальным KF5/KF6
  ConfigCore и использующий `KConfig::FullConfig`.
- Verifier запускается с hostile user и `kdedefaults/kdeglobals` state и
  полным platform-owned `XDG_CONFIG_DIRS`.
- Helper поставляется отдельным optional пакетом; headless `fic` не зависит
  от KDE runtime.

## Completed

- Collision audit актуальных KScreenLocker/Plasma Workspace/PowerDevil/
  plasma-desktop/KWin/System Settings не обнаружил unrelated consumers
  совпадающих `[Daemon]` keys.
- Backend переведён на dual-file prevalidation, merge и strict single-call
  verifier protocol.
- Добавлены helper source, conditional KF5/KF6 build, отдельные Deb/RPM
  package components и platform hierarchy.
- Обновлены unit/static tests и релевантная документация.
- Negative controls доказали обнаружение отсутствующей второй защиты,
  `NoGlobals` и неполного Ubuntu hierarchy.

## Changed areas

- `fic/src/modules/oss/desktop_environment/backends/KdeSystemBackend.*`
- `fic/kconfig-verifier/`, `fic/CMakeLists.txt`, platform profiles/resolver
- KDE/backend/platform tests
- Deb/RPM packaging и KDE architecture/session docs

## Validation

- Targeted build: KDE/GNOME backends, desktop reconciler/session/screenlock и
  platform profile targets — passed.
- Targeted CTest: 9/9 passed.
- Relevant Python static checks and packaging `bash -n` — passed.
- `FIC_BUILD_KCONFIG_VERIFIER=ON` configure correctly failed closed because
  this host lacks KF5 development files.
- Fresh multi-platform configure and the `fic` target could not be completed
  because this host also lacks libsystemd development metadata/headers.
- Real helper binary test was not built on this host. Earlier real KF6 runtime
  experiment confirmed that `FullConfig` can be overridden by hostile
  `kdedefaults/kdeglobals` until the matching protected system
  `kdeglobals` entry exists.
- Full project build was intentionally not run per task constraint.

## Remaining

- Run `kconfig_verifier_tests` and package builds in the target containers
  where KF5/KF6 development packages are available.
