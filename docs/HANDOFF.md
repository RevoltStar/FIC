# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-10.
- Ветка: `main`.
- Базовый commit: `8dca075`.
- Текущая задача: прототип compiled udev policy для Device Control.
- Реализация завершена, изменения рабочей копии не зафиксированы commit.

## Сделано

- `devices.db` является source of truth для desired device policy. Schema v2
  добавляет `devices.children_control` и singleton `device_policy_state` с
  desired/active revisions и состоянием трех категорийных DC-политик.
- Offline migration v0/v1 сохраняет устройства, переводит старое наследование
  в `children_control` и сохраняет существующий backup/verification contract.
- Добавлены `DevicePolicyCompiler` и `DevicePolicyActivator`:
  - deterministic generated `99-fic-devices.rules`;
  - приоритет identity, placement, DC category, nearest children rule, default;
  - safe USB/block identity или явная ошибка без широкого fallback;
  - escaping значений из БД;
  - полная запись `.tmp`, `fsync`, atomic rename, udev reload и восстановление
    предыдущего файла при неудачном reload.
- Generated rules обрабатывают remove отдельно, принимают ALLOW/DENY для
  add/change, выполняют DENY через `fic-dick enforce`, затем запускают
  `fic-dick udev` для inventory/history/PERMANENT.
- `fic-dick enforce` не использует SQLite: USB/usbmisc деавторизуется через
  ближайший `authorized`, block использует SCSI `device/delete` либо `remove`,
  PCI использует ближайший `remove`.
- Runtime daemon больше не принимает ALLOW/DENY по SQLite в hotplug path. Он
  сохраняет inventory/events, проверяет фактический результат DENY и сохраняет
  существующий PERMANENT/System Lock flow и reconciliation.
- Все административные изменения device policy после DB commit синхронно
  компилируют, активируют и reload'ят rules. Ошибка возвращает разные
  desired/active revisions. Уже подключенные устройства не деактивируются.
- Изменения категорийных DC-политик в `fic` передают полное состояние в
  root-only `device_regenerate_policy`; compiler читает его только из SQLite.
- IPC/CLI/GUI получили `children_control`; CLI также показывает policy status.
- Bootstrap rules теперь принадлежит install-компоненту/package `fic-dick`.
- Документация архитектуры и Device Control README обновлены; README содержит
  пример generated rules для дерева из ТЗ.

## Основные измененные файлы

- `fic-common/fic-device-db/include/fic/device-db/DB.h`, `src/DB.cpp`;
- `fic-common/fic-version/include/fic/version/ProductVersion.h.in`;
- `fic-dick/src/core/DeviceControlDaemon.cpp`, `src/main.cpp`;
- `fic-dick/src/modules/UDEVInfoCollector.cpp`, `fic-dick/CMakeLists.txt`;
- `fic/src/main.cpp`, `fic/CMakeLists.txt`;
- `fic-cli/src/main.cpp`;
- `fic-gui/src/DeviceTree.*`, `mainwindow.*`;
- `tests/device-control/*`, `tests/upgrade/UpgradeContractTests.cpp`;
- `docs/architecture-diagrams.md`, `fic-dick/README.md`;
- `packaging/deb/README.md`, `packaging/rpm/README.md`, `CHANGELOG.md`.

## Новые файлы

- `fic-dick/src/core/DevicePolicyCompiler.h`;
- `fic-dick/src/core/DevicePolicyCompiler.cpp`;
- `fic-dick/src/core/DeviceEnforcer.h`;
- `fic-dick/src/core/DeviceEnforcer.cpp`;
- `tests/device-control/DevicePolicyCompilerTests.cpp`.

## Выполненные проверки

- Полная сборка `cmake --build build-check -j2` для профиля `debian-12` —
  успешно.
- `ctest --test-dir build-check --output-on-failure -E release_contract_tests`
  — 28/28 успешно, три host-dependent теста корректно skipped.
- `device_policy_compiler_tests` проверяет ALLOW, DENY, PERMANENT, IGNORE,
  inheritance/precedence, category rule, identity, unsafe identity,
  determinism, escaping, rollback и `udevadm verify` — успешно.
- `device_tree_revision_tests` и `upgrade_contract_tests`, включая миграции
  v0 и v1 в v2 — успешно.
- `python3 tests/device-control/static_checks.py .` — успешно.
- `bash -n` для измененных device-control shell suites — успешно.
- Staged install компонента `fic-dick` через `DESTDIR` — bootstrap udev rule
  установлен с режимом `0644` — успешно.
- `git diff --check` — успешно.

## Что осталось

- Hardware/root suites `api`, `hierarchy`, `enforcement`, `coldboot` не
  запускались: они требуют управляемую VM и реально меняют udev/sysfs/device
  state.
- Полный CTest без исключений имеет один посторонний сбой:
  `release_contract_tests` ожидает 20 пакетов, а synthetic builders создают 25
  после добавления Ubuntu 26.04. Этот release-contract рассинхрон не относится
  к Device Control и в рамках задачи не исправлялся.

## Риски и ограничения прототипа

- Новая policy действует на следующий подходящий add/change; текущие устройства
  намеренно не деактивируются немедленно.
- DENY реализован только для `usb`, `usbmisc`, `block` и `pci`; backend остается
  близким к прежней sysfs-реализации и не является универсальным enforcement.
- Placement-independent identity намеренно отклоняется для USB interface, PCI и
  других записей без достаточно узких стабильных атрибутов.
- Если invalid desired identity переживет reboot, device daemon fail-closed не
  стартует до исправления desired DB; отдельного recovery plane у прототипа нет.
- `fic` и `fic-dick` используют взаимные синхронные admin IPC: редкое совпадение
  изменения DC-категории с PERMANENT lock request может завершиться timeout и
  потребовать reconciliation/retry. Полный async lock protocol не входит в ТЗ.
