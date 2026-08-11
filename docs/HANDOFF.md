# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-11.
- Ветка: `main`.
- Базовый commit: `e432d2f`.
- Текущая задача: разделение package-owned defaults и FIC-owned working configs.
- Реализация и локальные проверки завершены; изменения рабочей копии не
  зафиксированы commit.

## Сделано

- Добавлен централизованный `FIC_DEFAULT_CONFIG_DIR` со значением
  `/opt/fic/share/default-config` и соответствующий `FicRuntimePaths` path.
- CMake устанавливает семь исходных policy configs только как immutable
  defaults. В package payload остаётся пустой `/opt/fic/config`, но working
  `.conf` туда не устанавливаются.
- Добавлена команда `fic --maintenance ensure-config`. Она создаёт только
  отсутствующие working configs из defaults, сохраняет существующие regular
  files, ограничивает source размером 1 MiB и fail-closed отклоняет symlink и
  другие non-regular source/target paths.
- `AtomicFileWriter` получил режим exclusive atomic create: commit использует
  `renameat2(RENAME_NOREPLACE)` с атомарным hard-link fallback и не заменяет
  объект, появившийся в гонке.
- DEB больше не генерирует `DEBIAN/conffiles`; RPM больше не создаёт `%config`
  entries. В обоих post-install lifecycle `ensure-config` выполняется перед
  `begin-upgrade` и `migrate-config`.
- `migrateConfigs()` и `verifyConfigs()` не ослаблены: полный working config set
  по-прежнему обязателен.
- Upgrade tests покрывают fresh/idempotent/partial bootstrap, permissions,
  working symlink/directory, missing/default symlink/default directory,
  сохранение существующей конфигурации и последующую migration.
- Обновлены upgrade contract, архитектурные диаграммы, daemon и DEB/RPM README.
  Legacy conffile/%config migration намеренно не добавлялась.

## Основные изменённые файлы

- `cmake/FicInstallLayout.cmake`, `fic/CMakeLists.txt`;
- `fic-common/fic-core/include/fic/core/{AtomicFileWriter,FicPathDefaults,FicRuntimePaths,UpgradeManager}*`;
- `fic-common/fic-core/src/{AtomicFileWriter,FicRuntimePaths,UpgradeManager}.cpp`;
- `fic/src/main.cpp`, `fic/README.md`;
- `packaging/deb/build-fic-debian12-deb.sh`, `packaging/deb/README.md`;
- `packaging/rpm/build-fic-alt-p11-rpm.sh`, `packaging/rpm/README.md`;
- `tests/paths/RuntimePathsTests.cpp`, `tests/platform/static_checks.py`,
  `tests/upgrade/UpgradeContractTests.cpp`;
- `docs/upgrade-contract.md`, `docs/architecture-diagrams.md`.

## Выполненные проверки

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=debian-12` — успешно.
- Полная сборка `cmake --build build-check -j2` — успешно.
- `ctest --test-dir build-check --output-on-failure -E release_contract_tests`
  — 28/28 успешно; три host-dependent теста корректно skipped.
- `bash -n` для всех Debian-family builders и ALT p11 builder — успешно.
- `python3 tests/platform/static_checks.py .` и packaging/path static tests —
  успешно.
- Staged CMake install компонента `fic`: семь defaults присутствуют, working
  config directory не содержит `.conf` — успешно.
- Реальный `dist/fic_2.0.0~dev_debian12_amd64.deb`: defaults присутствуют,
  working `.conf` и `DEBIAN/conffiles` отсутствуют, postinst order проверен.
- Реальный `dist/fic-2.0.0~dev-1.altp11.x86_64.rpm`: defaults присутствуют как
  обычные файлы без config flags, working `.conf` отсутствуют, `%post` order
  проверен.
- `git diff --check` — успешно перед финальным handoff.

## Что осталось / границы проверки

- Полная установка/удаление DEB или RPM на disposable VM не выполнялась:
  maintainer scripts не запускались на хосте, чтобы не менять `/opt/fic`,
  systemd, udev и системную группу.
- Оба package builders собрали и выдали core `fic` packages. Полный общий run
  не завершил отдельный `fic-gui` package в текущем окружении из-за отсутствия
  обнаруживаемого Qt plugin directory; это не затрагивает проверенные core
  payload/scriptlets.
- `release_contract_tests` намеренно не запускался в полном CTest: известный
  посторонний рассинхрон ожидаемого числа package artifacts описан в предыдущем
  handoff и не относится к этой задаче.

## Риски и решения

- Новая packaging-схема является новой точкой отсчёта. Переход со старых
  conffile/%config packages не поддерживается согласно ТЗ.
- FHS layout не менялся: defaults и working state остаются под `/opt/fic`.
- Bootstrap не восстанавливает hostile/non-regular objects и никогда не
  обновляет существующий regular working config из более нового default.
