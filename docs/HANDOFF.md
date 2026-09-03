# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей незакоммиченной правки:
  `fe4bd82cca52efc3cfb452ed475b25cc7afd4a13`.

## Current task

- Привести dynamic Qt runtime в `fic-gui` DEB/RPM и release workflow к
  проверяемому LGPL/compliance contract без изменения лицензии FIC SUL-1.0.

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
- Официальный release fail-closed требует отдельно предоставленный
  `FIC_CORRESPONDING_SOURCE_DIR` с checksummed `corresponding-source.json`,
  покрывающий точные source package/version из всех GUI manifests.

## Completed

- DEB и ALT RPM используют общий closure/launcher/manifest implementation.
- В GUI payload добавлены canonical SUL/LGPL/GPL texts, package notices,
  `SOURCE_OFFER.md` и детерминированный `third-party-components.json` с
  package/source provenance и SHA-256 каждого Qt-файла.
- Manifest verifier требует точное совпадение payload, обязательные provenance
  fields, допустимый kind, существующие notice files и совпадающий SHA-256.
- DEB dependencies вычисляются для оставшихся system libraries и не содержат
  зависимости на system Qt packages.
- GUI RPM metadata: `License: SUL-1.0 AND LGPL-3.0-only`; compliance payload
  помечен как RPM `%doc` (ALT p11 RPM 4.13 не поддерживает `%license` file-list
  directive).
- Release manifest включает source index; бинарный release без точного source
  artifact set не создаётся.
- Добавлены static/contract tests и документация по license boundary,
  replacement, provenance и release source workflow.

## Changed areas

- Общий packaging compliance layer: `packaging/lib/`.
- DEB/RPM packaging scripts и builder images.
- Release workflow: `packaging/release/build-release.sh`.
- Packaging/release/third-party документация и GUI README.
- Packaging contract tests и их CTest registration.

## Validation

- `bash tests/integration/packaging/gui-runtime-compliance-test.sh .` — passed.
- `bash tests/common/version/release-contract-test.sh` — passed.
- `bash -n` для затронутых shell scripts, `python3 -m py_compile` для новых
  Python tools и `git diff --check` — passed.
- Полная сборка всех пяти packages на каждой поддерживаемой платформе:
  Debian 12, Debian 13, Ubuntu 24.04, Ubuntu 26.04 и ALT p11 — passed.
- Полная сборка всех пяти RPM packages в ALT p11 Podman — passed; Qt metadata
  notes дают только штатные `eu-elflint` warnings.
- Распакованные `fic-gui` DEB и RPM прошли exact manifest/SHA-256 verification,
  sidecar comparison и `--version` через default launcher, отдельный
  `FIC_QT_ROOT` и прямой `fic-gui.real` с явно заданными Qt paths.
- Все пять GUI packages содержат 12 Qt files и прошли post-unpack verifier.
  Source versions: Debian 12 `6.4.2+dfsg-10`, Debian 13
  `6.8.2+dfsg-9+deb13u2`, Ubuntu 24.04 `6.4.2+dfsg-21.1build5`, Ubuntu 26.04
  `6.10.2+dfsg-7`, ALT p11 `6.10.3-alt5`. `readelf` подтверждает Qt
  `DT_NEEDED`.
- Локальная перегенерация CTest остановилась до generate на отсутствующем
  host dependency `libsystemd`; новые tests поэтому запускались напрямую.

## Remaining

- Изменения не коммитить без явной команды пользователя.
- Реальный официальный release не создавался: пользовательский комплект
  corresponding source archives/index не предоставлен; проверен contract test
  с fixture.
- Полноценная интерактивная GUI-сессия/X11 не проверялась; проверена загрузка
  Qt runtime и ранний `--version` path.
