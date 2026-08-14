# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-14.
- Ветка: `main`.
- Базовый commit: `3731c6f` (`Исправляем baseline-рассинхроны`).
- Текущая задача: архитектурный рефакторинг модулей `fic` и страниц `fic-gui`
  для descriptor-driven UI и будущего `fic-web`.
- Реализация, сборка и тесты завершены; изменения рабочей копии не зафиксированы
  commit.

## Сделано

- `PolicyMap` заменён на `PolicyRegistry`: `PolicyModule` хранит `ModuleView`
  один раз вместе с картой подмодулей. `init_policyMap()` переименован в
  `initPolicyRegistry()`; семантика применения политик и отдельная FIREWALL
  reconciliation сохранены.
- `module_list` теперь возвращает `{name, view}` с `standard`, `device` или
  `audit`. IPC API поднят до версии 2. CLI и GUI переведены на новый контракт;
  неизвестный `view` отклоняется.
- Добавлен настоящий модуль `AUDIT` и `AUDIT.conf`. Политика `log_level`
  перенесена из `GLOBAL` в `AUDIT/logging`; Logger читает только
  `AUDIT/log_level` через общий `PolicyConfig`. Fallback на старое расположение
  отсутствует.
- Config schema поднята до версии 2, актуальные defaults синхронизированы,
  manifest конфигов расширен до девяти файлов. Поскольку стабильного релиза ещё
  нет, migration/compatibility path `1 -> 2` намеренно не добавлен.
- `MainWindow` сокращён до загрузки module descriptors и создания вкладок через
  `ModulePageFactory`.
- В GUI добавлены `ModuleDescriptor`, `PolicyDescriptor`, `PolicyService`,
  `DeviceService`, `StandardModulePage`, `DeviceModulePage`,
  `AuditModulePage` и переиспользуемый `PolicyEditorWidget`.
- `DeviceModulePage` владеет деревом, атрибутами, device controls и вкладками
  `Дерево устройств / Общие правила / События`; DC policies отображаются общим
  policy editor.
- `AuditModulePage` объединяет `LogViewer` и настройки AUDIT. `LogViewer` теперь
  сам создаёт и владеет своими controls вместо получения widgets из
  `MainWindow`.
- Legacy верхнеуровневые вкладки и ключи `[tab:DEVICES]`, `[tab:LOG]` удалены.
  Обе локали, README, upgrade contract и архитектурные диаграммы обновлены.
- Добавлены unit/static проверки registry, JSON module descriptors, Logger
  source, строгого GUI parsing, отсутствия tab-index assumptions и повторного
  использования policy editor.

## Основные изменённые зоны

- `fic/src/core/PolicyRegistry*`, `main_function.*`, `fic/src/main.cpp`;
- `fic/src/modules/audit/`, `fic/src/scripts/config/`, `fic/src/scripts/lang/`;
- `fic-common/fic-core/PolicyConfig`, Logger, LocalizationManager,
  UpgradeManager и version contract;
- `fic-cli/src/main.cpp`;
- `fic-gui/src/{models,services,pages,widgets}/`, `mainwindow.*`, `LogViewer.*`;
- `tests/module-ui/` и связанные contract/static tests;
- `README.md`, component README, `docs/architecture-diagrams.md`,
  `docs/upgrade-contract.md`, `AGENTS.md`.

## Выполненные проверки

- Конфигурация: `cmake -S . -B /tmp/fic-module-refactor-build
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- Полная сборка: `cmake --build /tmp/fic-module-refactor-build -j2` — успешно;
  собраны все компоненты и test targets.
- Полный `ctest --test-dir /tmp/fic-module-refactor-build --output-on-failure`
  — 36/36 без ошибок. `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` штатно пропущены как host-dependent.
- Staging install с `DESTDIR=/tmp/fic-module-refactor-install` — успешно;
  установлен `/opt/fic/share/default-config/AUDIT.conf` со schema 2.
- `git diff --check` — успешно.

## Ограничения и оставшиеся проверки

- Реальный daemon runtime API не запускался, чтобы не применять политики и не
  менять состояние build-хоста. JSON-контракт проверен unit/static tests.
- GUI собран, но не проверялся на реальном дисплее/VNC; визуальная компоновка и
  интерактивные device/log workflows требуют отдельной smoke-проверки в
  подходящем окружении.
- Реальные DEB/RPM Docker-сборки не запускались. Install rules и package
  resources проверены staging install и `packaging_build_resource_tests`.
- Миграция development schema 1 в schema 2 отсутствует намеренно; старый
  development state должен быть заменён/пересоздан до запуска schema 2.
