# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-14.
- Ветка: `main`.
- Базовый commit follow-up: `176abf2` (`PolicyMap заменён на PolicyRegistry с
  модульным ModuleView...`).
- Текущая задача: исправление контрактов последнего module/GUI refactor.
- Реализация и проверки завершены; `fic-web`, IPC API и config schema не
  изменялись.

## Сделано

- Удален `moduleViewForName()`. `PolicyRegistry` получил явные `addModule()` и
  `addPolicy()`, а production-builder регистрирует metadata всех девяти модулей
  до policies. Неизвестный module, конфликтующий `ModuleView` и duplicate
  policy завершают регистрацию ошибкой; пустой модуль допустим.
- Behavioral registry test использует production-builder и настоящие
  `AUDIT_log_level`/`GLOBAL_lang`. Проверены views `DC`, `AUDIT`, `DAC`,
  `GLOBAL`, структура `AUDIT/logging/log_level`,
  `GLOBAL/system_settings/lang`, отсутствие `GLOBAL/log_level` и ошибки
  регистрации.
- `parsePolicyDescriptors()` теперь строго проверяет daemon response и типы
  всех обязательных полей, optional `min`/`max`/`text_delimiter`, диапазон
  integer, module match и каждый элемент `possible_values`. JSON exceptions
  преобразуются в понятную protocol error.
- `PolicyService::applyChanges()` проверяет базовый response contract каждого
  set/enable/disable/apply запроса. Отказ `apply_module`, transport error и
  malformed response возвращаются как ошибка с сохранением daemon message;
  порядок и семантика mutation-команд не менялись.
- Все новые строки `DeviceModulePage`, копируемая сводка устройства,
  `LogViewer` и заголовки `LogModel` переведены на общие localization keys
  `[devices:ui]` и `[logs:ui]` в `ru.lang`/`en.lang`.
- Зафиксирована семантика: `AUDIT/log_level` фильтрует обычные записи `Logger`,
  но security audit trail административных IPC-запросов идет напрямую через
  `write_audit_log()` и остается always-on даже при `NoLog`. Описание policy и
  архитектурная документация синхронизированы.
- Контракт `module_list` остается массивом `{name, view}`; behavioral test
  проверяет сериализацию `PolicyModule::view`. `policy_list` не содержит
  `ModuleView`; IPC API не поднимался.

## Основные измененные зоны

- `fic/src/core/PolicyRegistry*`, `main_function.cpp`;
- `fic/src/main.cpp`, `README.md`, `fic/README.md`,
  `docs/architecture-diagrams.md`;
- `fic-gui/src/models/PolicyDescriptor.cpp`, `services/PolicyService.*`;
- `fic-gui/src/pages/DeviceModulePage.cpp`, `LogViewer.cpp`, `LogModel.cpp`;
- `fic/src/scripts/lang/{ru,en}.lang`;
- `tests/module-ui/` и `tests/CMakeLists.txt`.

## Выполненные проверки

- Конфигурация: `cmake -S . -B /tmp/fic-module-followup-build
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- Полная сборка: `cmake --build /tmp/fic-module-followup-build -j2` — успешно;
  собраны все компоненты и test targets.
- Полный `ctest --test-dir /tmp/fic-module-followup-build --output-on-failure`
  — 38/38 без ошибок. `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` штатно пропущены как host-dependent.
- Offscreen GUI startup с отсутствующими тестовыми daemon sockets — процесс
  успешно вошел в Qt event loop и был остановлен `timeout` через 3 секунды
  (`exit 124`); системное состояние не менялось.
- `git diff --check` — успешно.

## Ограничения и оставшиеся проверки

- Реальный daemon runtime API и policy apply не запускались, чтобы не менять
  состояние build-хоста. Security audit always-on проверен архитектурным
  запретом использования `Logger`; обычная фильтрация `AUDIT/log_level`
  проверена unit test, включая `NoLog`.
- GUI не проверялся на реальном дисплее/VNC и не проходил интерактивные device
  или log workflows. Offscreen smoke подтверждает только безопасный startup и
  обработку недоступного daemon.
- DEB/RPM Docker-сборки не запускались: packaging/runtime paths не менялись.
