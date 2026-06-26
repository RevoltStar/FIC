# fic-dick

`fic-dick` - компонент сбора и обновления базы устройств FIC. Название компонента сохранено из текущего проекта, но исполняемый файл и каталог приведены к нижнему регистру.

## Назначение

`fic-dick` отвечает за наполнение и актуализацию базы устройств, расположенной по пути:

```text
/opt/fic/db/devices.db
```

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

Пакетное udev-правило выбирает только подсистемы `usb`, `pci` и `block`.
Фильтрации подсистем внутри `UDEVInfoCollector` нет: если список подсистем
нужно изменить, это делается в `fic/src/scripts/udev/99-fic-devices.rules`.

Для работы режима `udev` ожидаются переменные окружения, которые предоставляет udev:

- `ACTION` - действие, например `add`, `change`, `remove`;
- `DEVPATH` - путь устройства в дереве udev;
- `SUBSYSTEM` - подсистема устройства.

Поддерживаемая логика:

- helper пересылает `ACTION`, `DEVPATH`, `SUBSYSTEM` и udev environment в `fic-dick --daemon`;
- helper делает одну IPC-попытку и быстро завершается, если device daemon еще не готов;
- daemon добавляет, обновляет или помечает устройство отключенным;
- daemon вычисляет effective policy и применяет USB/PCI/block enforcement best-effort;
- если обязательных переменных окружения нет, обработка завершается с ошибкой.

## Режим check-permanent

```bash
fic-dick check-permanent
```

Отправляет daemon команду проверки `permanent` устройств. Если обязательное
устройство отсутствует, daemon вызывает `lock` через основной `fic` socket.

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
- `block` - `BlockInfoCollector`;
- `pci` - `PCIInfoCollector`.

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

и вызывает инициализацию схемы через `DB::initializeDatabase()`.

Если база не может быть инициализирована, компонент пишет ошибку в лог и завершает работу с кодом `1`.

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

## Сборка

Из корня проекта:

```bash
cmake -S . -B build-check
cmake --build build-check --target fic-dick
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
