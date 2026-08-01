# fic-dick

`fic-dick` - компонент сбора и обновления базы устройств FIC. Название компонента сохранено из текущего проекта, но исполняемый файл и каталог приведены к нижнему регистру.

## Назначение

`fic-dick` отвечает за наполнение и актуализацию базы устройств, расположенной по пути:

```text
/opt/fic/db/devices.db
```

Сам `fic-device-db` этот production path не знает: `fic-dick` строит
`DevicePaths` из общего runtime layout и передает в `DB` явный `DBOptions`
с путями базы, lock-файла и debug-log. Это позволяет тестам и нестандартным
сборкам использовать изолированное хранилище без глобальных констант.

Демон `fic` применяет обычные политики ОС, а `fic-dick --daemon` является владельцем дерева устройств, `devices.db`, udev-событий и исполнения решений контроля устройств. GUI и CLI обращаются к дереву устройств через `/run/fic/fic-device.sock`.

## Основные режимы запуска

Компонент запускается с обязательным аргументом режима:

```bash
fic-dick [--daemon|udev|check-permanent|wait-daemon|cpu_board_memory]
```

Если режим не указан, программа завершится с ошибкой.

## Режим daemon

Основной runtime-режим:

```bash
fic-dick --daemon
```

Daemon слушает Unix-сокет:

```text
/run/fic/fic-device.sock
```

Через него обслуживаются команды дерева устройств: чтение корня, детей и
атрибутов, назначение `blocked`/`allowed`/`permanent`/`ignored`, переключение
`ignore_hierarchy`, сброс правила до наследования, удаление отключенных
исторических поддеревьев и проверка отсутствующих `permanent` устройств.

Read-only команда `device_tree_revision` возвращает целочисленную ревизию
данных устройств. Ревизия увеличивается SQLite-триггерами при изменениях
`devices`, `device_attributes` и `device_events`. GUI опрашивает только эту
команду каждые пять секунд и перечитывает дерево, только если значение
изменилось.

Общие настройки DC (`block_usb_storage`, `block_printers_scanners`,
`block_optical_drives`) применяются к устройствам при их подключении или
переподключении. Они намеренно не отключают устройства, которые уже были
подключены в момент изменения настройки администратором.

Каждая из этих политик имеет фиксированное внутреннее значение `true`;
единственным переключателем поведения является ее статус `ENABLE`/`DISABLE`.

`device_children` по умолчанию возвращает только актуальное дерево текущей
загрузки: системные контейнеры и устройства с текущим `boot_id`. Исторические
отключенные ветки остаются в БД, но возвращаются только при явном
`include_disconnected=true`. GUI использует это как переключатель
«Показать историю», чтобы администратор видел текущую топологию отдельно от
прошлых экземпляров устройств.

## Режим udev

Режим `udev` используется как короткий helper для обработки событий устройств.

```bash
fic-dick udev
```

Обычно этот режим запускается не вручную, а из udev-правила:

```text
fic/src/scripts/udev/99-fic-devices.rules
```

Правило вызывает:

```text
/opt/fic/bin/fic-dick udev
```

Пакетное udev-правило выбирает только подсистемы `usb`, `usbmisc`, `pci` и
`block`.
Фильтрации подсистем внутри `UDEVInfoCollector` нет: если список подсистем
нужно изменить, это делается в `fic/src/scripts/udev/99-fic-devices.rules`.

Для работы режима `udev` ожидаются переменные окружения, которые предоставляет udev:

- `ACTION` - действие, например `add`, `change`, `remove`;
- `DEVPATH` - путь устройства в дереве udev;
- `SUBSYSTEM` - подсистема устройства.

Поддерживаемая логика:

- helper пересылает `ACTION`, `DEVPATH`, `SUBSYSTEM` и udev environment в `fic-dick --daemon`;
- helper делает одну IPC-попытку и быстро завершается, если device daemon еще не готов;
- отсутствие `/run/fic/fic-device.sock` во время раннего coldplug не считается ошибкой helper: boot-time `fic-udevadm-trigger` позже выполнит контролируемый retrigger после `wait-daemon`;
- daemon принимает IPC-команду `udev_event` только от root peer credentials;
- daemon добавляет, обновляет или помечает устройство отключенным;
- daemon вычисляет effective policy и применяет USB/PCI/block enforcement с
  несколькими короткими retry-попытками. Для дочерних USB-функций, например
  `/dev/usb/lp0`, USB enforcement ищет ближайший родительский sysfs-файл
  `authorized`;
- если обязательных переменных окружения нет, обработка завершается с ошибкой.

## Режим check-permanent

```bash
fic-dick check-permanent
```

Отправляет daemon команду проверки `permanent` устройств. Если обязательное
устройство отсутствует, daemon вызывает `lock` через основной `fic` socket.
Проверка выполняется по стабильной идентичности устройства (`device_hash` +
`subsystem`), а не по одному историческому экземпляру дерева. При remove-событии
проверяется все отключенное поддерево, чтобы исчезновение обязательного
потомка не терялось за событием родителя.

## Режим wait-daemon

```bash
fic-dick wait-daemon [timeout_seconds]
```

Ожидает готовности `/run/fic/fic-device.sock`, отправляя daemon команду
`status`. Режим используется `fic-udevadm-trigger` перед `udevadm trigger`,
чтобы boot-time udev-события не терялись из-за запуска раньше готовности
`fic-dick --daemon`.

## Поддерживаемые подсистемы

Для некоторых подсистем создаются специализированные коллекторы:

- `usb` - `USBInfoCollector`;
- `usbmisc` - базовый `UDEVInfoCollector` для устройств вроде `/dev/usb/lp0`;
- `block` - `BlockInfoCollector`;
- `pci` - `PCIInfoCollector`.

`USBInfoCollector` выбирает поля идентификации по `DEVTYPE`: физическое
USB-устройство идентифицируется отдельно от USB-интерфейсов, а интерфейсы
дополнительно учитывают `INTERFACE` и `MODALIAS`. Это позволяет видеть функции
составных устройств, например МФУ, отдельными узлами вместо схлопывания
нескольких интерфейсов в один.

`BlockInfoCollector` выбирает поля идентификации после получения текущего udev
environment. Для partitions приоритет отдается `ID_PART_ENTRY_UUID`, затем
`ID_FS_UUID`, затем сочетанию `ID_SERIAL + ID_PART_ENTRY_NUMBER`, с fallback на
`DEVNAME`, `MAJOR/MINOR` или `DEVPATH`.
Виртуальные block-устройства `/devices/virtual/block/...` также принимаются
udev-коллектором, чтобы device-mapper/loop/ram/zram записи могли попадать в
дерево устройств.

`PCIInfoCollector` использует базовые PCI-поля и добавляет weak-disambiguator:
`PCI_SLOT_NAME`, а если его нет — `DEVPATH`. Такие записи получают атрибуты
`FIC_IDENTITY_STRENGTH=weak` и `FIC_IDENTITY_DISAMBIGUATOR`, чтобы GUI/CLI и
администратор могли видеть, что устройство различено по топологии, а не только
по сильной аппаратной идентичности.

Для остальных подсистем используется базовый `UDEVInfoCollector` с набором стабильных udev-полей:

- `DEVPATH`;
- `SUBSYSTEM`;
- `DEVTYPE`;
- `MODALIAS`.

## Режим cpu_board_memory

Режим `cpu_board_memory` собирает информацию о CPU, материнской плате и памяти:

```bash
fic-dick cpu_board_memory
```

В этом режиме используются:

- `CPUInfoCollector`;
- `BoardInfoCollector`;
- `MemoryInfoCollector`.

Обычно режим запускается systemd-unit-файлом:

```text
fic/src/scripts/service/fic_get_device_info.service
```

Unit вызывает:

```text
/opt/fic/bin/fic-dick "cpu_board_memory"
```

## Инициализация базы данных

В режиме `--daemon` база открывается и блокируется на время конкретного запроса.
В режиме `cpu_board_memory` компонент открывает базу напрямую:

```text
/opt/fic/db/devices.db
```

и вызывает проверку/инициализацию схемы через `DB::initializeDatabase()`.

Если база не может быть инициализирована, компонент пишет ошибку в лог и завершает работу с кодом `1`.
Существующая база идентифицируется через SQLite `application_id=0x46494344`, а
версия схемы хранится в `user_version`. Обычный runtime принимает только точную
текущую версию и ничего не ремонтирует. Offline migration выполняется только
явной root-командой `fic-dick --maintenance migrate-db`: перед транзакцией она
создаёт SQLite Backup API-копию в `/opt/fic/state/db-backups`, затем проверяет
`quick_check`, внешние ключи и итоговую версию. Проверить схему без изменения
можно через `fic-dick --maintenance check-db`.

Служебная таблица `device_tree_state` содержит единственную строку с текущей
ревизией. Триггеры ревизии входят как в `DB::initializeDatabase()`, так и в
поставляемую seed-базу.

## Логи

Компонент использует общий `Logger` и пишет сообщения с категорией:

```text
devices
```

Для отладки udev-событий дополнительно используется файл:

```text
/opt/fic/log/fic-debug.log
```

Туда записываются PID, `ACTION`, `DEVPATH` и `SUBSYSTEM` текущего события.
Мутирующие device IPC-команды дополнительно пишутся в audit-log текущей
загрузки вместе с peer uid/gid/pid, кратким описанием запроса и результатом.
Команда `device_events` принимает только `limit` от 1 до 500, чтобы выборка и
IPC-ответ оставались ограниченными.

## Сборка

Из корня проекта:

```bash
cmake -S . -B build-check
cmake --build build-check --target fic-dick
```

Статические проверки компонента запускаются через CTest:

```bash
ctest --test-dir build-check --output-on-failure
```

Отдельная сборка компонента:

```bash
cmake -S fic-dick -B build-fic-dick
cmake --build build-fic-dick
```

## Зависимости

Компонент использует:

- C++17;
- SQLite3;
- OpenSSL Crypto;
- общие утилиты FIC для работы с файлами, логами и конфигурацией;
- системную информацию Linux и udev-переменные окружения.

## Установка

В пакетах исполняемый файл устанавливается как:

```text
/opt/fic/bin/fic-dick
```

Связанные файлы:

- `/opt/fic/db/devices.db` - основная база устройств;
- `/opt/fic/share/devices.seed.db` - seed-база, устанавливаемая пакетом;
- `/etc/udev/rules.d/99-fic-devices.rules` - правило обработки udev-событий;
- `fic_get_device_info.service` - сбор CPU/board/memory;
- `fic_get_device_udev_info.service` - запуск udev-trigger.

## Типовой сценарий проверки

1. Проверить, что база доступна:

```bash
ls -l /opt/fic/db/devices.db
```

2. Собрать информацию о CPU, плате и памяти:

```bash
sudo /opt/fic/bin/fic-dick cpu_board_memory
```

3. Запустить повторную генерацию udev-событий:

```bash
sudo /opt/fic/bin/fic-udevadm-trigger
```

4. Проверить логи устройства:

```bash
sudo tail -n 100 /opt/fic/log/fic-debug.log
```

## Взаимодействие с другими компонентами

- `fic` применяет политики и может использовать данные, которые собирает `fic-dick`.
- `fic-gui` может отображать сведения из базы устройств.
- `fic-cli` напрямую не управляет `fic-dick`, но может использоваться для применения политик после обновления базы.
- Общий доступ к SQLite-базе устройств находится в `fic-common/fic-device-db`; `fic-dick` линкуется с этой библиотекой вместо прямого подключения исходников из компонента `fic`.

## Важные правила разработки

- Новые типы устройств лучше добавлять через отдельный collector-класс.
- Режим `udev` должен быстро завершаться, потому что запускается из udev-событий.
- Обработка удаления устройства должна быть безопасной и не должна удалять чужие записи.
- Все ошибки и диагностические сообщения должны попадать в общий лог FIC или debug-log для udev.
