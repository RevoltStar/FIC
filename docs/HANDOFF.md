# Контроль устройств: правила, статическая инвентаризация, инциденты

### Current base

Branch `main`; исходный commit задачи `cf07f42bcc8afaccf8dec6e5a9dee8fbf10fd2ff`.

### Current task

Привести модуль контроля устройств в соответствие с согласованной архитектурой:
предварительный отказ изменения индивидуальных правил, наследование `/` и
`/devices`, три политики серьёзности и три вида detector-событий, достоверность
статической инвентаризации, инцидент неудачной блокировки динамического
устройства, GUI/локализация.

### Accepted architecture / invariants

* Авторитетный контракт: `docs/device-control.md`. Он описывает отказ изменения
  правил для подключённых динамических устройств, сохранение правила для
  присутствующего статического оборудования, наследование виртуальных
  контейнеров, по-бутовый proof статической инвентаризации и три вида нарушений
  с независимыми политиками и retry-обязательствами.
* Общий расчёт эффективного правила: `fic-dick/src/device/EffectiveDevicePolicy.*`
  (используется демоном и предварительной оценкой правил). Предварительная
  оценка — `fic-dick/src/daemon/DeviceRuleChange.*`, одна на все четыре команды.
* IPC kinds/commands/policy mapping: `fic-common/fic-ipc/include/fic/ipc/DeviceIncidentProtocol.h`.
  Отправитель и строгий разбор ACK: `fic-dick/src/daemon/DeviceIncidentSender.*`.
* Политики `static_device_present_severity` (NONE) и
  `device_block_failed_severity` (STANDARD) включены по умолчанию и не являются
  настройками udev. Аддитивное обновление существующей установки:
  `ConfigSchemaManager::ensureDeviceIncidentSeverityDefaults()`; полностью
  отсутствующая политика использует заводское значение, присутствующая но
  недостоверная — fail-closed ISOLATE.
* Статический proof: `/run/fic/static-inventory.state`
  (`fic-dick/src/device/StaticInventoryProof.*`). Демон сам наблюдает proof,
  коллектор не вызывает IPC (нет циклической зависимости сервисов).
* failed-block нельзя перепроверить из инвентаризации: установленный факт
  хранится в памяти демона и повторяется; после рестарта восстанавливается
  следующим udev-событием.

### Completed

Этапы 1–4 реализованы: предварительный отказ правил и наследование `/`,
`/devices`; обобщённый IPC трёх видов нарушений и три политики серьёзности с
аддитивным обновлением конфигурации; достоверность статической инвентаризации и
обнаружение запрещённого статического оборудования; инцидент неудачной
блокировки; GUI/CLI-сообщения, локализация, документация; регрессионные тесты.

### Changed areas

`fic-dick/src/{daemon,device,collectors,policy}`, `fic/src/{main.cpp,daemon,modules/dc,resources}`,
`fic-common/{fic-core,fic-ipc}`, `fic-gui/.../DeviceTree.*`, `fic-cli/src/main.cpp`,
`tests/{fic-dick,fic,common,integration}`, `docs/device-control.md`, README,
`docs/architecture-diagrams.md`.

### Validation

Host (Ubuntu 26.04, g++ 15), `build-dc`: полная сборка проекта и полный CTest.
Целевые наборы: `device_rule_change_tests`, `static_inventory_proof_tests`,
`device_severity_config_upgrade_tests`, `device_policy_compiler_tests`,
`device_incident_*`, `permanent_device_*`, `schema_contract_tests`,
`device_control_static_checks`, `IncidentApplyRoutingChecks.py`.
Docker/VM device-control suites не запускались.

### Remaining

Не выполнялись: Docker-гейт `static_hardware_ipc_gate.py` (обновлён под новый
контракт), VM device-control suites (`enforcement.sh` обновлён), матрица пяти
дистрибутивов. Известное ограничение: после перезапуска демона до подтверждения
доставки failed-block восстанавливается только следующим udev `add/change`.
Посторонняя неточность: `docs/architecture-diagrams.md` всё ещё описывает
категорийные политики как `true`-политики (устарело до этой задачи).
