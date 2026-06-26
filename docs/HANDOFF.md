# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-26.
- Ветка: `main`.
- Базовый commit: `c4f92a7` (`Добавляем доки для агента`).
- Текущая задача: реализация базовой архитектуры и поведения компонента
  "Контроль устройств".

## Сделано

- `fic-dick` получил режим `--daemon` с Unix-сокетом
  `/run/fic/fic-device.sock`.
- `fic-dick udev` стал коротким helper: он пересылает `ACTION`, `DEVPATH`,
  `SUBSYSTEM` и udev environment в device-daemon, а не пишет БД сам.
- Device-daemon обслуживает API дерева устройств:
  `device_root`, `device_get`, `device_children`, `device_attributes`,
  `device_update_control_level`, `device_update_ignore_hierarchy`,
  `device_reset_control`, `device_delete`, `device_events`,
  `device_check_permanent`.
- Из `fic` daemon убрана работа с деревом устройств и зависимость от
  `fic-device-db`/SQLite. Старые `device_*` команды возвращают понятную ошибку,
  что device API обслуживается `fic-dick`.
- В `devices` добавлено поле `control_explicit`, чтобы отличать явно заданное
  правило администратора от стартового наследования.
- Effective policy вычисляется в device-daemon:
  - `ignored` наследуется на поддерево;
  - собственное явное правило устройства побеждает родителя;
  - `ignore_hierarchy=true` у явного правила той же идентичности действует
    глобально;
  - общие DC-настройки применяются ниже явного правила устройства;
  - неизвестные устройства наследуют ближайшее явное правило родителя или
    системный default `allowed`.
- API отклоняет операции, после которых подключенное устройство получило бы
  effective=`blocked`.
- API запрещает назначать `permanent` отсутствующему устройству.
- При отключении/отсутствии effective=`permanent` device-daemon вызывает
  `lock` у основного `fic` daemon. Auto-unlock не реализован намеренно.
- Добавлено best-effort исполнение:
  - USB: запись в sysfs `authorized`;
  - PCI: sysfs `remove`;
  - block: sysfs `device/delete` или ближайший `remove`.
- После успешного блокирующего sysfs-действия device-daemon сбрасывает `boot_id`
  у заблокированного поддерева.
- `UDEVInfoCollector` умеет принимать env-map от daemon и сохраняет в БД все
  полезные udev-атрибуты, а identity-хэш строит только по контрольным полям.
- Исправлено поведение при переносе устройства в другой порт: при
  `ignore_hierarchy=false` создается новая occurrence, старая ветка не
  перезаписывается.
- Исправлен поиск родителя при remove-событии: родитель ищется по
  `devpath + boot_id`, а не по subsystem ребенка.
- Identity block/PCI скорректирован:
  - из PCI identity убран `PCI_SLOT_NAME`;
  - из block identity убраны `ID_PATH`, `DEVNAME`, `MAJOR`, `MINOR`
    для обычных дисков/разделов.
- `DC.conf` заменен на policy-config с общими флагами:
  `block_usb_storage`, `block_printers_scanners`, `block_optical_drives`.
- `DC` зарегистрирован в `PolicyMap` как config-only модуль демона `fic`.
- GUI дерева устройств переведен на `/run/fic/fic-device.sock`, показывает
  assigned/effective/explicit, умеет переключать `ignore_hierarchy` и сбрасывать
  правило до наследования.
- GUI больше не ищет root по hardcoded `id=1`; используется `device_root`.
- GUI показывает ошибки device-daemon пользователю через `QMessageBox`.
- CLI получил команды `device root/get/children/set/ignore-hierarchy/reset`
  и `device check-permanent`.
- Добавлен `fic-device.service`, обновлены udev rule и coldplug-trigger:
  `add|change|remove`, `udevadm settle`, затем `fic-dick check-permanent`.
- Обновлены CMake install rules, Debian 10/11/12 packaging, ALT p11 packaging,
  README packaging и архитектурные диаграммы.

## Измененные файлы

Ключевые зоны изменений:

- `fic-dick/src/core/DeviceControlDaemon.*`
- `fic-dick/src/main.cpp`
- `fic-dick/src/modules/*InfoCollector*`
- `fic-common/fic-device-db/*`
- `fic-common/fic-ipc/include/fic/ipc/FicIpcClient.h`
- `fic/src/main.cpp`, `fic/CMakeLists.txt`
- `fic/src/modules/dc/*`, `fic/src/scripts/config/DC.conf`
- `fic-gui/src/DeviceTree.*`, `fic-gui/src/mainwindow.cpp`
- `fic-cli/src/main.cpp`
- `fic/src/scripts/service/*`, `fic/src/scripts/udev/99-fic-devices.rules`
- `packaging/deb/*`, `packaging/rpm/*`
- `docs/architecture-diagrams.md`, component/package README files.

Изменения не закоммичены.

## Проверки

Выполнено:

```bash
cmake -S . -B /tmp/fic-device-control-build
cmake --build /tmp/fic-device-control-build -j2
git diff --check
```

Результат: успешно собраны `fic`, `fic-session-agent`, `fic-cli`, `fic-dick`,
`fic-gui` и общие библиотеки. `git diff --check` замечаний не выдал.

Runtime-проверки с реальным systemd, udev, sysfs enforcement, lock/unlock и
записью в `/opt/fic` не выполнялись, потому что они меняют состояние хоста.
Пакетные Docker-сборки deb/rpm не запускались.

## Известные решения и ограничения

- `fic-dick udev` fail-closed: если `fic-dick --daemon` не доступен, helper
  завершится ошибкой, а не будет писать БД напрямую.
- USB enforcement реализован через sysfs `authorized`, но глобальный
  `authorized_default=0` намеренно не включается автоматически: это опасно без
  полноценного recovery/runbook и может отрубить ввод.
- PCI и native block enforcement остаются best-effort: userspace не гарантирует
  блокировку до первичной инициализации ядром.
- `permanent` с `ignore_hierarchy=true` считается выполненным, если подключена
  хотя бы одна occurrence той же идентичности.
- `ignored` у родителя сильнее собственного правила потомка, потому что принято
  решение трактовать ignored как исключение всего поддерева из контроля.
- Старые строки БД при миграции получают `control_explicit=1`, чтобы не
  превращать прежние админские решения в наследуемые.
- `fic_get_device_info.service` для CPU/board/memory пока оставлен direct-DB
  режимом. Основное udev-дерево переведено на daemon.
- Recovery-процедура для случаев блокировки ввода/критичного устройства пока
  не оформлена отдельным runbook.

## Что осталось

- Провести интеграционную проверку в тестовой VM: systemd startup order,
  `/run/fic/fic-device.sock`, udev add/change/remove, coldplug trigger,
  permanent-lock сценарий.
- Проверить реальные sysfs paths для USB/block/PCI на целевых дистрибутивах.
- При необходимости добавить recovery-документ для администратора.
- Решить, надо ли переносить `cpu_board_memory` в socket API device-daemon.
- Пакетные сборки deb/rpm запускать отдельно, когда будет готов тестовый
  Docker/CI-прогон.

## Как продолжать в новой сессии

1. Прочитать `AGENTS.md` и этот файл.
2. Выполнить `git status --short` и сверить базовый commit.
3. Если задача касается контроля устройств, начинать с
   `fic-dick/src/core/DeviceControlDaemon.cpp`,
   `fic-common/fic-device-db`, `fic-gui/src/DeviceTree.*` и
   `docs/architecture-diagrams.md`.
4. Не запускать реальные udev trigger, sysfs enforcement, lock/unlock или
   package install без явного запроса пользователя и подходящего тестового
   окружения.
