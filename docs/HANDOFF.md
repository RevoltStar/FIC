# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-14.
- Ветка: `main`.
- Базовый commit задачи: `a1efecc` (`Исправить контракты PolicyRegistry и
  module GUI`).
- Текущая задача: fail-closed инициализация production `PolicyRegistry`.
- Реализация и проверки завершены. IPC API, config schema, `ModuleView`, GUI,
  `fic-web`, форматы `module_list`/`policy_list` и семантика самих policies не
  менялись.

## Сделано

- `initPolicyRegistry()` возвращает явный `bool`/`error` и строит production
  registry во временном объекте. Текущий registry заменяется через атомарный
  для состояния `swap` только после успешного создания и регистрации всех
  policies. Исключения фабрики или регистрации преобразуются в ошибку; пустой
  registry больше не используется как сигнал сбоя.
- Первичная ошибка построения registry завершает daemon с ненулевым кодом до
  создания административного socket и до policy apply.
- `reload_config`, `apply_all`, `apply_module` и `apply_policy` возвращают API
  error при failed rebuild и сохраняют последний корректный in-memory
  registry. Apply после такой ошибки не начинается.
- После успешной записи `set_policy_value`, `enable_policy` или
  `disable_policy` failed reload возвращает сообщение, что конфигурация уже
  сохранена, но registry не перезагружен. Зависимая DC regeneration при этом
  не выполняется.
- Startup/periodic apply pass прекращается сразу после failed rebuild, не
  запускает policy apply и FIREWALL reconciliation, возвращает `false` и
  записывает причину в stderr и security audit. Periodic loop может продолжить
  работу с последним корректным registry.
- Registry tests проверяют успешную инициализацию, точный набор descriptor-ов
  всех девяти production modules, расположение `AUDIT/logging/log_level` и
  `GLOBAL/system_settings/lang`, отсутствие `GLOBAL/log_level`, а также
  сохранение существующего registry при unknown module, duplicate policy и
  исключении фабрики policies.
- Документация daemon lifecycle и IPC mutation/apply flow синхронизирована с
  fail-closed поведением.

## Основные измененные зоны

- `fic/src/core/PolicyRegistry.h`;
- `fic/src/core/PolicyRegistryInitialization.*`;
- `fic/src/core/main_function.*`;
- `fic/src/main.cpp`;
- `tests/module-ui/ModuleRegistryTests.cpp`;
- `fic/README.md`, `docs/architecture-diagrams.md`, `docs/HANDOFF.md`.

## Выполненные проверки

- `cmake -S . -B /tmp/fic-registry-failclosed-build
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build /tmp/fic-registry-failclosed-build -j2` — успешно; собраны
  все компоненты и test targets.
- `ctest --test-dir /tmp/fic-registry-failclosed-build --output-on-failure` —
  38/38 без ошибок. `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` штатно пропущены как host-dependent.
- `git diff --check` — успешно.

## Ограничения и оставшиеся проверки

- Реальный daemon, policy apply, FIREWALL reconciliation, DC regeneration и
  другие проверки, меняющие состояние хоста, не запускались.
- Ошибочные startup/runtime ветви проверены unit-тестом общей транзакционной
  границы registry и статически по daemon control flow; отдельный runtime
  fault-injection daemon test не добавлялся, чтобы не расширять архитектуру
  этой сфокусированной задачи.
- DEB/RPM Docker-сборки не запускались: packaging и runtime paths не менялись.
