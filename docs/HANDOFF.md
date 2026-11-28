# Контроль устройств: исправление дефектов принятой архитектуры

### Current base

Branch `main`; исходный commit задачи `b98ecf6cfd9c2485b56c5700ec8eb1aec5c565f6`.

### Current task

Устранить дефекты реализации контроля устройств: потеря ожидающих инцидентов
неудачной блокировки, подавление повторного запрета статического оборудования
кэшем, недостаточная достоверность статической инвентаризации, потеря
категориального failed-block без записи в БД, виртуальные узлы как динамические
устройства, маскирующая повреждения миграция `DC.conf`, дефекты жизненного
цикла static-inventory proof, лишняя повторная попытка sysfs enforcement и
несовпадение Docker-гейта с IPC-контрактом.

### Accepted architecture / invariants

* Авторитетный контракт: `docs/device-control.md`.
* Общий расчёт эффективного правила: `fic-dick/src/device/EffectiveDevicePolicy.*`
  (в нём же явная классификация `is_static_hardware_subsystem` /
  `is_dynamic_hardware_subsystem`). Предварительная оценка правил —
  `fic-dick/src/daemon/DeviceRuleChange.*`.
* Обязательства доставки failed-block: `daemon/BlockFailureObligation.h`
  (merge-only, подтверждение закрывает ровно отправленный набор, ограничение
  `MAX_DEVICE_INCIDENT_IDS`).
* IPC kinds/commands/policy mapping: `fic-common/fic-ipc/include/fic/ipc/DeviceIncidentProtocol.h`.
  Отправитель и строгий разбор ACK: `fic-dick/src/daemon/DeviceIncidentSender.*`.
  Только `incident_device_block_failed` может нести `device_paths` и пустой
  `device_ids` (устройство категориального DENY может отсутствовать в БД).
* Статический proof: `/run/fic/static-inventory.state`
  (`fic-dick/src/device/StaticInventoryProof.*`) с `published_at_ns`; коллектор
  аннулирует proof до сбора и завершается с ошибкой, если публикация не удалась.
  Наблюдение обработанных публикаций — `daemon/StaticProofWatch.h`
  (публикация считается обработанной только после успешных статических проверок).
* Аддитивное обновление `DC.conf`: `ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults`
  добавляет ТОЛЬКО `static_device_present_severity` и `device_block_failed_severity`
  и только при полном отсутствии политики; `permanent_device_missing_severity`
  миграцией не восстанавливается.
* failed-block нельзя перепроверить из инвентаризации: установленный факт
  хранится в памяти демона и повторяется; после рестарта восстанавливается
  следующим udev-событием.

### Completed

Все подтверждённые дефекты задания устранены: merge-only обязательства
failed-block, снята дедупликация статических инцидентов, достоверность
инвентаризации CPU/Board/Memory, категориальный failed-block без записи в БД
(`device_paths`), явная классификация виртуальных узлов, групповая миграция
`DC.conf`, жизненный цикл proof (метка публикации, типобезопасное чтение,
аннулирование до сбора, retry после ошибки БД, ненулевой код при ошибке
публикации), удалена лишняя повторная попытка sysfs enforcement, исправлен
Docker-гейт. Добавлены регрессионные тесты и статические проверки.

### Changed areas

`fic-dick/src/{daemon,device,collectors}`, `fic/src/main.cpp`,
`fic-common/fic-core/src/config/ConfigSchemaManager.cpp`,
`tests/{fic-dick,fic,common,integration}`, `docs/device-control.md`.

### Validation

Host (Ubuntu 26.04, g++ 15), `build-dc`:

* полная сборка проекта (`cmake --build build-dc -j4`): 205/205, EXIT=0;
* полный `ctest --test-dir build-dc`: 241/242 passed. Единственный отказ —
  `display_manager_transaction_tests` («DM filesystem tests require disposable
  root container»), не связан с устройством и требует root/контейнер;
* новые/обновлённые наборы: `block_failure_obligation_tests`,
  `static_proof_watch_tests`, `static_inventory_parse_tests`,
  `static_inventory_proof_tests`, `device_rule_change_tests`,
  `permanent_device_incident_tests`, `device_severity_config_upgrade_tests`,
  `schema_contract_tests`, `device_control_static_checks` — PASS;
* `python3 tests/integration/device-control/static_checks.py .` — PASS;
* `git diff --check` — PASS.

Docker (одноразовый контейнер `debian:12` + build deps, mirror `mirror.yandex.ru`,
потому что `deb.debian.org` в этом окружении зависает на крупных загрузках):

* `static_hardware_ipc_gate.py` — PASS
  («static IPC updates, unchanged udev rules, later USB activation, missing
  permanent CPU scan»).

### Remaining

* VM device-control suites (`tests/integration/device-control/suites/`) не
  выполнялись: нет хоста с USB-фикстурой. Матрица пяти дистрибутивов остаётся на
  GitHub Actions.
* Известное ограничение: после перезапуска демона до подтверждения доставки
  failed-block восстанавливается только следующим udev `add/change`.
* Посторонние (не исправлялись) дефекты, обнаруженные по ходу задачи:
  * `tests/integration/device-control/category_ipc_gate.py` не создаёт фикстуру
    package-lifecycle (`/var/lib/fic-lifecycle/status`), поэтому
    `fic --maintenance incident-init` отказывает в lifecycle admission и гейт
    падает до проверок (дефект существовал до этой задачи);
  * схема `device_events` (`fic-common/fic-device-db/src/DB.cpp`) не разрешает
    `event_type='incident'`, поэтому журнальные записи инцидентов не
    сохраняются (ошибка игнорируется, логируется на DEBUG) — тоже до этой задачи;
  * `docs/architecture-diagrams.md` всё ещё описывает категорийные политики как
    `true`-политики.
