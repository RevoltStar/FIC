# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей незакоммиченной правки:
  `274f2fc0cc487bd4c6af4838db42658026e9beb4`.

## Current task

- Закрыть оставшиеся Qt compliance/verification gaps без изменения принятой
  архитектуры dynamic Qt bundle.

## Accepted architecture / invariants

- FIC остаётся под SUL-1.0; Qt-компоненты документируются и лицензируются
  отдельно. Корневой `LICENSE` не изменён.
- `fic-gui.real` остаётся динамически связанным с Qt. Launcher выбирает
  `/opt/fic/qt` по умолчанию и полностью переключается на непустой
  `FIC_QT_ROOT`, позволяя заменить bundled Qt без изменения executable.
- Bundle строится как recursive ELF closure от `fic-gui.real`,
  `platforms/libqxcb.so` и `imageformats/libqjpeg.so`: Qt6 из `qt6-base`
  включается, package-owned non-Qt остаётся системным, unowned/unresolved или
  другой Qt source package отклоняется.
- Release остаётся fail-closed и требует точный Corresponding Source set.
- Изменения не коммитить без отдельной явной команды пользователя.

## Completed

- `fic-gui --license-info` выводит FIC/Qt license boundary до создания
  `QApplication`; добавлен display-independent test.
- Добавлен безопасный internal `--gui-smoke-test`: реальный `QApplication`,
  `QWidget`, JPEG decoding через plugin и короткий event loop без `MainWindow`
  и daemon.
- Packaging smoke под Xvfb проверяет default bundle и отдельный
  `FIC_QT_ROOT`; Qt/plugin diagnostics и dynamic-loader trace подтверждают
  фактическую загрузку Qt Core/Gui/Widgets, XCB и JPEG из выбранного root.
- Runtime manifest schema 1 проверяет непустой полный список notice files,
  безопасные пути и SHA-256 каждого notice. License metadata обозначена как
  package-level summary, а не per-file conclusion.
- Corresponding Source schema 1 семантически проверяет Debian `.dsc` и полный
  `Checksums-Sha256` set, либо настоящий SRPM через RPM metadata; добавлены
  требуемые negative tests.
- Документация обновлена под новые пользовательский notice, schema и release
  gate.

## Changed areas

- GUI entry point и linking: `fic-gui/src/app/main.cpp`,
  `fic-gui/CMakeLists.txt`.
- Compliance/release tools: `packaging/lib/`.
- DEB/RPM builder images и packaging documentation.
- Packaging contract tests и CTest registration.
- `docs/third-party-licensing.md`, `docs/release-process.md`,
  `fic-gui/README.md`.

## Validation

- Shell syntax checks, Python compile checks, `git diff --check` — passed.
- `gui-runtime-compliance-test.sh`, `release-contract-test.sh`,
  `corresponding-source-test.sh` — passed на host; RPM test реально собрал и
  проверил SRPM и binary RPM fixtures.
- Standalone `fic-gui` configure/build и `fic-gui-license-info-test.sh` —
  passed.
- Пересобраны реальные `fic-gui` packages для Debian 12, Debian 13,
  Ubuntu 24.04, Ubuntu 26.04 и ALT p11 — passed.
- Каждый из пяти распакованных packages прошёл manifest/notice verifier,
  `--license-info`, Xvfb smoke для default и отдельного override Qt root,
  loader-origin assertions и проверку unresolved system dependencies.
- Qt closure сохранился на 12 components на каждой платформе.
- Полная сборка в Debian 12 container — passed. CTest там: 58/60 passed;
  только два git-dependent shell test не запустились из-за отсутствия `git` в
  builder image. Оба тех же test отдельно на host — passed; в совокупности все
  60 tests подтверждены, но не одним CTest invocation.

## Remaining

- Публичный release не создавался: не предоставлены реальные точные distro
  `.dsc` sets и ALT SRPM для версий Qt из пяти runtime manifests. Release gate
  остаётся fail-closed; семантика проверена на synthetic Debian descriptor set
  и реально собранных RPM fixtures.
- Host-wide CMake configure невозможен без development dependency
  `libsystemd`; полная сборка выполнена в Debian 12 builder container.
- ALT RPM auto-generated metadata по-прежнему содержит ELF requirements на Qt
  SONAME/symbol capabilities, хотя loader smoke доказывает использование
  bundled Qt. Это поведение принятого RPM packaging flow не менялось в текущем
  узком scope.
