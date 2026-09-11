# FIC: передача контекста

## Current base

- Ветка `main`.
- База: `7c2be45`.

## Current task

- Полностью удалить неиспользуемую KDE global KConfig architecture, сохранив
  KDE `screenlock_timeout` в режиме `SessionOnly`.

## Accepted architecture / invariants

- GNOME и FLY — `MandatoryGlobal`; KDE и XFCE — `SessionOnly`; LXQt —
  `Unsupported`.
- KDE `screenlock_timeout` применяется к обнаруженным Plasma-сессиям через
  `KdeScreenLockTimeoutHandler`, `KdeBackend`, `kreadconfig5/6`,
  `kwriteconfig5/6` и `org.kde.screensaver.configure`.
- KDE не создаёт global requirements и не заявляет machine-wide immutable
  KConfig authority.

## Completed

- Удалены verifier target/source, KDE system backend, их tests и platform
  metadata.
- Удалены KF ConfigCore discovery/dependencies, stale CMake options и generated
  executable path.
- DEB/RPM packaging выпускает пять пакетов и не содержит verifier package или
  KF ConfigCore build dependency.
- Static/contract tests и документация приведены к текущей архитектуре.

## Changed areas

- Desktop global backend registration и KDE documentation.
- Platform executable/profile metadata и CMake.
- DEB/RPM build scripts, container dependencies и packaging README.
- Удалённые backend/verifier tests и связанные static contracts.

## Validation

- Clean configure: `build-kconfig-removal`, Ubuntu 24.04 profile — passed с
  локальным `/tmp` shim для отсутствующего `libsystemd-devel`; KF ConfigCore не
  искался.
- Full build: `cmake --build build-kconfig-removal -j2` — passed.
- Full CTest вне sandbox: 83 passed, 1 root-only test skipped, 0 failed.
- Первый sandbox CTest дал два permission-specific failure; оба targeted tests
  прошли вне sandbox до финального полного прогона.
- `bash -n` для DEB/RPM build scripts — passed.
- Repository-wide searches по удалённым identifiers и KF ConfigCore
  dependencies — no matches.
- `ldd`/`readelf -d` для собранного `fic` — KDE framework dependencies нет.
- `git diff --check` — passed.

## Remaining

- Изменения не закоммичены.
