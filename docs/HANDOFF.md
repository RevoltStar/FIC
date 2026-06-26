# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-26.
- Ветка: `main`.
- Базовый commit: `befcfd6` (`Исправляем баги сокетов`).
- Текущая задача: исправить пустое дерево устройств после boot и падение
  `fic_get_device_info.service` при отсутствии command hash.

## Что было обнаружено на машине `172.17.1.105`

- После предыдущих unit-fix пакетов `fic.service` и `fic-device.service`
  стартуют, `/run/fic/fic.sock` и `/run/fic/fic-device.sock` существуют с
  правами `root:fic 0660`.
- `fic-cli status` работает, `fic-cli device root` возвращает seed-root.
- Дерево устройств почти пустое: есть только `/`, `/cpu_list`, `/memory_list`,
  `/board_list`, `/devices`, `/devices/pci0000:00`; ниже `/devices/pci0000:00`
  детей нет.
- В boot-логах `fic-dick udev` массово падал с:
  `connect(/run/fic/fic-device.sock) failed: No such file or directory`.
- Причина: `fic_get_device_udev_info.service` запускал `fic-udevadm-trigger`
  сразу после старта `fic-device.service`. Так как `fic-device.service` имеет
  `Type=simple`, systemd считает сервис запущенным до того, как daemon реально
  создал и начал слушать `/run/fic/fic-device.sock`.
- `fic_get_device_udev_info.service` завершался `SUCCESS`, потому что
  `udevadm trigger/settle` не считает ошибки `RUN+=/opt/fic/bin/fic-dick udev`
  ошибкой самого `udevadm`.
- `fic_get_device_info.service` отдельно падал с core dump:
  `Failed to execute lscpu command: no stored reference hash was found for executable: /usr/bin/lscpu`.

## Сделано

- `fic-udevadm-trigger` теперь перед `udevadm trigger --action=add` вызывает:
  `fic-dick wait-daemon 15`.
- В `fic-dick` добавлен служебный режим:
  `fic-dick wait-daemon [timeout_seconds]`.
  Он опрашивает `/run/fic/fic-device.sock` командой `status` и возвращает 0
  только после реальной готовности device daemon.
- В `fic-dick udev` добавлен retry отправки udev-события в daemon:
  до 50 попыток с паузой 100 мс, но только для ошибок подключения к Unix-сокету.
  Ошибки самой обработки `udev_event` не ретраятся.
- В `CPUInfoCollector`, `BoardInfoCollector`, `MemoryInfoCollector` добавлен
  fallback: если `VerifiedProcessExecutor::execute` неуспешен, команда не
  запускается в обход проверки; вместо этого создается фиктивное устройство
  (`[Неизвестный процессор]`, `[Неизвестная материнская плата]`,
  `[Неизвестная оперативная память]`).
- Для `MemoryInfoCollector` сохранен существующий fallback на `/proc/meminfo`,
  если и обычный `dmidecode` не сработал или не дал пригодных модулей памяти.
- Обновлен `fic-dick/README.md` с описанием режима `wait-daemon`.
- На машине `172.17.1.105` никаких правок, рестартов сервисов, package install
  или повторного `udevadm trigger` не выполнялось; использовалась только
  диагностика.

## Измененные файлы

- `fic/src/scripts/service/fic-udevadm-trigger`
- `fic-dick/src/core/DeviceControlDaemon.cpp`
- `fic-dick/src/core/DeviceControlDaemon.h`
- `fic-dick/src/main.cpp`
- `fic-dick/src/modules/CPUInfoCollector.cpp`
- `fic-dick/src/modules/BoardInfoCollector.cpp`
- `fic-dick/src/modules/MemoryInfoCollector.cpp`
- `fic-dick/README.md`
- `docs/HANDOFF.md`

Также в рабочем дереве остаются предыдущие незакоммиченные fix-файлы:

- `fic/src/scripts/service/fic.service`
- `fic/src/scripts/service/fic_get_device_info.service`
- `fic/src/scripts/service/fic-notify.service`
- `fic/CMakeLists.txt`
- `packaging/deb/build-fic-debian10-deb.sh`
- `packaging/deb/build-fic-debian11-deb.sh`
- `packaging/deb/build-fic-debian12-deb.sh`
- `packaging/rpm/build-fic-alt-p11-rpm.sh`

## Проверки

Выполнено:

```bash
git status --short
sh -n fic/src/scripts/service/fic-udevadm-trigger
rg -n "wait-daemon|wait_for_daemon|unknown .*placeholder|Неизвест" fic-dick/src fic/src/scripts/service/fic-udevadm-trigger
```

Перед текущими изменениями уже выполнялись:

```bash
bash -n packaging/deb/build-fic-debian10-deb.sh packaging/deb/build-fic-debian11-deb.sh packaging/deb/build-fic-debian12-deb.sh packaging/rpm/build-fic-alt-p11-rpm.sh
git diff --check
```

Нужно выполнить после текущих изменений:

```bash
git diff --check
cmake -S . -B build-check
cmake --build build-check --target fic-dick -j2
```

Не выполнялось по просьбе пользователя в предыдущем шаге:

- сборка deb/rpm пакетов;
- установка пакетов;
- runtime-рестарты сервисов на тестовой машине.

## Что проверить после пересборки и установки пакетов

1. Перезагрузить тестовую машину.
2. Проверить:
   - `systemctl status fic.service fic-device.service fic_get_device_udev_info.service fic_get_device_info.service`;
   - `stat -c '%U %G %a %n' /run/fic /run/fic/fic.sock /run/fic/fic-device.sock`;
   - `fic-cli status`;
   - `fic-cli device root`;
   - `fic-cli device children 5`;
   - `fic-cli device children 6`.
3. В journal не должно быть массовых ошибок
   `connect(/run/fic/fic-device.sock) failed`.
4. `fic_get_device_info.service` не должен падать из-за отсутствия hash для
   `/usr/bin/lscpu`; в дереве должен появиться placeholder
   `[Неизвестный процессор]`, если verified-запуск невозможен.
