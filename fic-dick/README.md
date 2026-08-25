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

Демон `fic` применяет обычные политики ОС, а `fic-dick --daemon` является
владельцем дерева устройств, desired policy в `devices.db`, компиляции active
udev policy, initial reconciliation и runtime udev-ingestion. GUI и CLI обращаются к
дереву устройств через `/run/fic/fic-device.sock`. Runtime udev-события
поступают отдельно через `/run/fic/fic-device-events.sock` и не конкурируют с
административным API.

## Основные режимы запуска

Компонент запускается с обязательным аргументом режима:

```bash
fic-dick [--daemon|udev|enforce|reconcile|check-permanent|wait-daemon|cpu_board_memory|--version|--build-info]
```

Если режим не указан, программа завершится с ошибкой.
`--version` и `--build-info` не инициализируют production paths и доступны для
проверки пакета до установки или запуска демона.

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
`ignore_hierarchy`, изменение `children_control=allow|deny|inherit`, сброс
правила до наследования, удаление отключенных
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
После изменения статуса `fic` синхронно передает полное состояние категорий в
device API. `fic-dick` сохраняет его в `device_policy_state`, после чего
compiler читает desired policy только из SQLite.

## Компиляция и активация policy

`DevicePolicyCompiler` читает один snapshot `devices.db` и детерминированно
генерирует `/etc/udev/rules.d/99-fic-devices.rules`. Приоритет решения:

1. direct identity для `ignore_hierarchy=true`;
2. direct placement по точному `ENV{DEVPATH}`;
3. категорийная DC policy;
4. ближайший explicit `children_control` предка;
5. global default `ALLOW`.

`PERMANENT` и `IGNORE` разрешают подключение; `PERMANENT` дополнительно
проверяется daemon при исчезновении identity. `IGNORE` не распространяется на
потомков. Для `children_control=inherit` правило не генерируется.

`DevicePolicyActivator` полностью пишет `99-fic-devices.rules.tmp`, выполняет
`fsync`, атомарный `rename` и `udevadm control --reload-rules`. При ошибке
reload предыдущий файл восстанавливается. SQLite хранит `desired_revision` и
`active_revision`; ошибка compilation/activation оставляет предыдущую active
revision и возвращается административному клиенту.

Direct identity компилируется только из достаточно узких стабильных полей:
USB device требует vendor, product и serial; block использует UUID/WWN/serial
из существующей identity-модели. Для USB interface, PCI и других weak identity
compiler отклоняет `ignore_hierarchy=true`, не создавая широкий wildcard.

Для дерева из прототипного ТЗ фрагмент реально генерируемого body выглядит так
(ID в `FIC_POLICY_SOURCE` зависят от конкретной БД):

```udev
# DEFAULT ENV VARIABLES
ENV{FIC_DEVICE_LEVEL}="UNKNOWN", ENV{FIC_INHERITED_LEVEL}="UNKNOWN", ENV{FIC_DIRECT_MATCH}="0", ENV{FIC_POLICY_SOURCE}="global-default"

# INHERITED RULES
ENV{DEVPATH}=="/devices/pci0000:00/*", ENV{FIC_INHERITED_LEVEL}="DENY", ENV{FIC_POLICY_SOURCE}="children:6"
ENV{DEVPATH}=="/devices/pci0000:00/0000:00:02.1/*", ENV{FIC_INHERITED_LEVEL}="ALLOW", ENV{FIC_POLICY_SOURCE}="children:20"
ENV{DEVPATH}=="/devices/pci0000:00/0000:00:02.1/0000:02:00.0/usb1/*", ENV{FIC_INHERITED_LEVEL}="DENY", ENV{FIC_POLICY_SOURCE}="children:23"

# DIRECT PLACEMENT RULES
ENV{DEVPATH}=="/devices/pci0000:00/0000:00:02.1/0000:02:00.0", ENV{FIC_DIRECT_MATCH}="1", ENV{FIC_DEVICE_LEVEL}="DENY", ENV{FIC_POLICY_SOURCE}="placement:21"
ENV{DEVPATH}=="/devices/pci0000:00/0000:00:02.1/0000:02:00.0/usb1/1-1", ENV{FIC_DIRECT_MATCH}="1", ENV{FIC_DEVICE_LEVEL}="ALLOW", ENV{FIC_POLICY_SOURCE}="placement:24"

# POLICY DECISION
ENV{FIC_DIRECT_MATCH}=="1", ENV{FIC_EFFECTIVE_LEVEL}="$env{FIC_DEVICE_LEVEL}"
ENV{FIC_DIRECT_MATCH}!="1", ENV{FIC_INHERITED_LEVEL}!="UNKNOWN", ENV{FIC_EFFECTIVE_LEVEL}="$env{FIC_INHERITED_LEVEL}"
ENV{FIC_EFFECTIVE_LEVEL}=="", ENV{FIC_EFFECTIVE_LEVEL}="ALLOW", ENV{FIC_POLICY_SOURCE}="global-default"
ENV{FIC_CONNECTION_LEVEL}=="", ENV{FIC_CONNECTION_LEVEL}="$env{FIC_EFFECTIVE_LEVEL}"

# SUBSYSTEM ENFORCEMENT
ENV{FIC_CONNECTION_LEVEL}=="DENY", RUN+="/opt/fic/bin/fic-dick enforce"

# NOTIFY FIC-DICK
RUN+="/opt/fic/bin/fic-dick udev"
```

В этом примере `/`, `/devices` не превращаются в опасные direct `/*` rules;
interface `.../1-1:1.0` наследует DENY от `usb1`, а direct ALLOW для `1-1`
имеет приоритет над inherited policy.

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

Обычно этот режим запускается не вручную, а из сгенерированного udev-правила:

```text
fic/src/scripts/udev/99-fic-devices.rules
```

Правило вызывает:

```text
/opt/fic/bin/fic-dick udev
```

Пакет устанавливает только bootstrap rule. При старте daemon заменяет его
policy, скомпилированной из БД. Generated rule выбирает только подсистемы
`usb`, `usbmisc`, `pci` и `block`.
Фильтрации подсистем внутри `UDEVInfoCollector` нет: если список подсистем
нужно изменить, это делается в `fic/src/scripts/udev/99-fic-devices.rules`.

Для работы режима `udev` ожидаются переменные окружения, которые предоставляет udev:

- `ACTION` - действие, например `add`, `change`, `remove`;
- `DEVPATH` - путь устройства в дереве udev;
- `SUBSYSTEM` - подсистема устройства.

Поддерживаемая логика:

- helper сериализует `ACTION`, `DEVPATH`, `SUBSYSTEM` и udev environment в один
  bounded JSON datagram;
- datagram отправляется в отдельный Unix socket
  `/run/fic/fic-device-events.sock`;
- socket создается device daemon как `SOCK_DGRAM`, включает `SO_PASSCRED` и
  принимает события только от root sender credentials;
- helper не ждет завершения DB/sysfs/enforcement обработки и быстро
  завершается;
- если событие невозможно доставить, helper оставляет bounded runtime marker
  `/run/fic/fic-device-reconcile.required`; после восстановления daemon
  выполняет full reconciliation;
- daemon кладет валидные события в bounded RAM queue, coalesce'ит redundant
  `change` для одного `SUBSYSTEM + DEVPATH`, а тяжелую обработку выполняет
  последовательно;
- при overflow queue daemon не теряет состояние молча: выставляет
  reconciliation-required и перечитывает фактическое состояние устройств;
- daemon добавляет, обновляет или помечает устройство отключенным через тот же
  processing pipeline, который используется initial reconciliation;
- до запуска inventory helper generated rule уже вычисляет effective policy;
- при DENY rule сначала запускает `fic-dick enforce`, который не открывает
  SQLite: USB/usbmisc пишет `authorized=0`, PCI использует только `remove`
  самого `DEVPATH` с подтверждённым sysfs subsystem `pci`, а block — только `delete`
  ancestor с подтверждённым sysfs subsystem `scsi`; если безопасный SCSI
  `delete` отсутствует, block enforcement завершается ошибкой и никогда не
  поднимается к PCI `remove`;
- затем `fic-dick udev` передает environment с `FIC_EFFECTIVE_LEVEL` и
  `FIC_POLICY_SOURCE` daemon для inventory, history и PERMANENT handling;
- если обязательных переменных окружения нет, обработка завершается с ошибкой.

Udev event stream не является единственным источником истины. Событие означает,
что состояние устройства могло измениться; authoritative состояние берется из
текущего udev/sysfs inventory. Поэтому потеря runtime event во время downtime
или overflow восстанавливается full reconciliation.

Изменение policy не деактивирует уже подключённое устройство. Новый generated
файл гарантированно используется при следующем подходящем `add/change`.

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
`status`. Режим используется `fic-udevadm-trigger` перед reconciliation.
Boot inventory больше не строится через массовый `udevadm trigger`; device
daemon сам выполняет initial reconciliation при старте.

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
версия схемы хранится в `user_version`. Схема поддерживает `children_control` и
`device_policy_state` с desired/active revisions и статусами DC-категорий.
Schema 1 является первой и единственной поддерживаемой версией. Команда
`fic-dick --maintenance initialize-db` создаёт отсутствующую или пустую базу
сразу с полным текущим layout, metadata и baseline rows. Существующая непустая
база не изменяется и принимается только при точном совпадении `application_id`,
`user_version`, layout, indexes, triggers и baseline rows. Проверить схему без
изменения можно через `fic-dick --maintenance check-db`.

Служебная таблица `device_tree_state` содержит единственную строку с текущей
ревизией. Триггеры ревизии создаются `DB::initializeDatabase()` вместе с
остальной schema 1; seed-база не поставляется.

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
- `/etc/udev/rules.d/99-fic-devices.rules` - правило обработки udev-событий;
- `fic_get_device_info.service` - сбор CPU/board/memory;
- `fic_get_device_udev_info.service` - ожидание initial reconciliation и
  проверка `permanent` устройств.

## Типовой сценарий проверки

1. Проверить, что база доступна:

```bash
ls -l /opt/fic/db/devices.db
```

2. Собрать информацию о CPU, плате и памяти:

```bash
sudo /opt/fic/bin/fic-dick cpu_board_memory
```

3. Проверить готовность device daemon и обязательные устройства:

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
