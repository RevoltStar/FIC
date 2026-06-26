# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-26.
- Ветка: `main`.
- Базовый commit: `0d2cfeb` (`Теперь подсистемы отсеиваем на уровне udev-правила, в UDEVInfoCollector убираем отсеивание`).
- Текущая задача: убрать остаточный boot-шум от ранних udev-событий, исправить
  идентификацию block partitions и добавить weak-дизамбигуацию PCI-устройств.

## Контекст диагностики на `172.17.1.105`

- После установки версии с commit `0d2cfeb` загрузка стала нормальной:
  `Startup finished in 1.778s (kernel) + 4.974s (userspace) = 6.753s`.
- `fic.service` и `fic-device.service` работают, `fic_get_device_udev_info.service`
  и `fic_get_device_info.service` завершаются `SUCCESS`.
- Дерево уже не пустое: есть PCI/USB/block-ветки, CPU/board/memory placeholder'ы.
- Остались три наблюдения:
  1. В раннем coldplug до готовности `/run/fic/fic-device.sock` `fic-dick udev`
     быстро завершался с exit code 1, из-за чего `systemd-udevd` писал шумные
     сообщения. После controlled retrigger ошибок уже не было.
  2. В sysfs были `sda`, `sda1`, `sda2`, `sda5`, `sr0`, а в БД только
     `sda`, `sda5`, `sr0`. Причина: `BlockInfoCollector` выбирал control list
     в конструкторе через process env, а в daemon mode udev env устанавливался
     позже через `set_udev_env`.
  3. PCI bridge `0000:00:05.0` и `0000:00:1e.0` имели одинаковые
     `PCI_CLASS`, `PCI_ID`, `PCI_SUBSYS_ID`; без дополнительного признака они
     неразличимы и могут оставаться virtual/схлопываться.

## Сделано в текущем рабочем дереве

- `fic-dick udev` теперь считает отсутствие device socket во время раннего
  coldplug ожидаемой ситуацией:
  - если IPC-ошибка ровно `connect(/run/fic/fic-device.sock) failed: No such file...`,
    helper пишет TRACE и возвращает `0`;
  - остальные ошибки daemon/API по-прежнему возвращают `1`.
- В `UDEVInfoCollector` добавлены hooks:
  - `control_list_for_current_env()`;
  - `refresh_control_list()`;
  - `extra_device_attributes()`;
  - `device_note_suffix()`.
- `set_udev_env()` и операции create/remove теперь пересобирают control list по
  текущему udev environment до вычисления hash.
- `BlockInfoCollector` больше не использует `std::getenv()` в конструкторе для
  выбора полей. Для partitions используется порядок:
  1. `DEVTYPE + ID_PART_ENTRY_UUID + ID_SERIAL`;
  2. `DEVTYPE + ID_FS_UUID + ID_SERIAL`;
  3. `DEVTYPE + ID_SERIAL + ID_PART_ENTRY_NUMBER`;
  4. `DEVTYPE + DEVNAME`;
  5. `DEVTYPE + MAJOR + MINOR`;
  6. `DEVTYPE + DEVPATH`.
- `PCIInfoCollector` реализует вариант Б: к базовым PCI-полям добавляется
  weak-disambiguator `PCI_SLOT_NAME`, а если его нет — `DEVPATH`.
- Для PCI weak identity добавляются атрибуты:
  - `FIC_IDENTITY_STRENGTH=weak`;
  - `FIC_IDENTITY_DISAMBIGUATOR=<PCI_SLOT_NAME|DEVPATH>`.
- В `notes` PCI-устройств добавляется пометка:
  `weak PCI identity disambiguated by ...`.
- Обновлен `fic-dick/README.md`.

## Измененные файлы

- `fic-dick/src/core/DeviceControlDaemon.cpp`
- `fic-dick/src/modules/UDEVInfoCollector.cpp`
- `fic-dick/src/modules/UDEVInfoCollector.h`
- `fic-dick/src/modules/BlockInfoCollector.cpp`
- `fic-dick/src/modules/BlockInfoCollector.h`
- `fic-dick/src/modules/PCIInfoCollector.cpp`
- `fic-dick/src/modules/PCIInfoCollector.h`
- `fic-dick/README.md`
- `docs/HANDOFF.md`

## Проверки

Выполнено:

```bash
git status --short
git diff --check
cmake -S . -B /tmp/fic-build-check
cmake --build /tmp/fic-build-check --target fic-dick -j2
```

`fic-dick` успешно собран в `/tmp/fic-build-check`.

Не выполнялось:

- сборка deb/rpm пакетов;
- установка пакетов;
- runtime-рестарты сервисов на тестовой машине;
- повторный `udevadm trigger`;
- запуск `fic-dick udev` локально, чтобы не писать runtime-логи в `/opt/fic`.

## Что проверить после пересборки и установки пакетов

1. Перезагрузить тестовую машину.
2. Проверить скорость:
   - `systemd-analyze time`;
   - `systemd-analyze blame | head -n 30`.
3. Проверить шум early coldplug:
   - `journalctl -b -u systemd-udevd --no-pager | grep fic-dick`;
   - ожидаемо не должно быть `Process '/opt/fic/bin/fic-dick udev' failed with exit code 1`
     из-за отсутствующего `/run/fic/fic-device.sock`.
4. Проверить дерево:
   - `fic-cli device root`;
   - `fic-cli device children 5`;
   - `fic-cli device children 6`;
   - пройти до block-ветки `sda`.
5. Сверить block с sysfs:
   - в БД должны появиться `sda`, `sda1`, `sda2`, `sda5`, `sr0` для текущей
     тестовой машины.
6. Сверить PCI bridge:
   - `0000:00:05.0` и `0000:00:1e.0` должны стать реальными `pci`, а не
     оставаться `__virtual__`;
   - у них должны быть атрибуты `FIC_IDENTITY_STRENGTH=weak` и
     `FIC_IDENTITY_DISAMBIGUATOR=PCI_SLOT_NAME`.

## Решения и риски

- “Дизамбигуация” здесь означает снятие неоднозначности: когда сильные
  идентификаторы не позволяют отличить два устройства, добавляется
  дополнительный признак.
- Для PCI выбран практичный вариант Б: дерево должно показывать реальные узлы,
  поэтому `PCI_SLOT_NAME`/`DEVPATH` используется как weak-disambiguator. Это
  менее стабильно, чем настоящая аппаратная идентичность, поэтому явно
  маркируется атрибутами и notes.
- Изменение PCI hash может создать новые записи для уже встречавшихся PCI-узлов
  при следующей загрузке/trigger. Проект находится в разработке, миграция
  текущей БД не добавлялась.
