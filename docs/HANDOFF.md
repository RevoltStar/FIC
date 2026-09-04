# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей незакоммиченной правки:
  `f064316aa87e5c0763eeebca01f95a4a209e65ba`.

## Current task

- Исправить RPM license notice discovery, доказать clean ALT p11 installation
  bundled Qt и уточнить `fic-gui --license-info` без изменения schema 1.

## Accepted architecture / invariants

- FIC остаётся под SUL-1.0; Qt dynamically linked и отдельно лицензируется.
- Bundled Qt root остаётся `/opt/fic/qt`, `FIC_QT_ROOT` остаётся механизмом
  полной замены root.
- `third-party-components.json` и Corresponding Source schema остаются version 1.
- Изменения не коммитить без отдельной явной команды пользователя.

## Completed

- RPM notices выбираются по `%{FILENAMES}` + `%{FILEFLAGS:fflags}` с приоритетом
  `%license`; filename regex удалён. Узкий ALT p11 fallback принимает только
  `%doc` regular files непосредственно из versioned `qt6-base-common` doc root.
- Добавлен реальный Fedora RPM fixture: `%license` MIT/BSD обнаруживаются,
  обычный `%doc` README исключается, удалённый declared license приводит к fail.
- Для `fic-gui` отфильтрованы только generated `libQt6*` Requires; остальные
  automatic dependencies сохранены, остаточные Qt Requires являются build error.
- Добавлен clean ALT p11 test с обычным `apt-get`: до и после установки/запуска
  Qt RPM отсутствуют; default и override Xvfb smoke загружают bundled Qt.
- `--license-info` прямо называет GNU LGPL version 3 where applicable и сохраняет
  границы SUL/Qt/alternative/embedded third-party terms.
- Все пять ALT RPM пересобраны из текущего дерева в
  `/tmp/fic-alt-runtime-output`.

## Changed areas

- RPM manifest discovery и ALT RPM builder: `packaging/lib/`, `packaging/rpm/`.
- Disposable packaging tests: `tests/integration/packaging/`.
- GUI notice и синхронизированная документация: `fic-gui/`,
  `docs/third-party-licensing.md`.

## Validation

- Все пять ALT p11 RPM rebuilt successfully.
- Итоговый `fic-gui`: `License: SUL-1.0 AND LGPL-3.0-only`, no `libQt6*`
  Requires, `Provides: fic-gui = 0.0.0~alpha-1.altp11`.
- Manifest: schema 1, 12 Qt components from `qt6-base-6.10.3-alt5`, 38
  RPM-declared notices и 37 unique packaged notice contents.
- `gui-runtime-compliance-test.sh`, `corresponding-source-test.sh`,
  `release-contract-test.sh`, `build-resources-test.sh` — passed.
- Fedora RPM file-flags fixture — passed in disposable Podman container.
- Clean ALT p11 ordinary dependency installation — passed; `fic`, `fic-dick`,
  `fic-gui` installed, no system Qt before/after, manifest and exact license-info
  contract passed.
- Installed Xvfb smoke passed for `/opt/fic/qt` and copied `FIC_QT_ROOT`;
  loader checks covered Qt Core/Gui/Widgets, XCB and JPEG plugin origins.
- Shell syntax, Python compile checks и `git diff --check` — passed.

## Remaining

- Публичный release не создавался. Release gate по-прежнему требует exact
  Corresponding Source set (real `.dsc` sets для Debian-family и matching
  `qt6-base-6.10.3-alt5.src.rpm` для ALT), exact tag/version и clean tree.
- Package signing, SBOM generation и publication остаются отдельной release
  engineering работой согласно существующему release contract.
