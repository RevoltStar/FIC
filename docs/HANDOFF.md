# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-26.
- Ветка: `main`.
- Базовый commit: `aad9754` (`Реализация базовой архитектуры и поведения модуля "Контроль устройств"`).
- Текущая задача: исправить ownership и lifecycle runtime-каталога `/run/fic`
  для основного `fic` daemon и `fic-dick --daemon`.

## Сделано

- Подтверждено на ALT Workstation K 11.3 p11, что оба сервиса используют один
  `RuntimeDirectory=fic`; при рестартах systemd может удалять сокет соседнего
  демона или пересоздавать `/run/fic` с некорректным ownership.
- Принято архитектурное решение: `/run/fic` остается общей IPC-зоной FIC
  (`root:fic 0770`), а `/run/fic/fic.sock` и `/run/fic/fic-device.sock`
  остаются в одном каталоге с правами `root:fic 0660`.
- Из `fic.service` и `fic-device.service` удалены `RuntimeDirectory=fic` и
  `RuntimeDirectoryMode=0770`, чтобы два unit-файла не владели lifecycle одного
  каталога.
- Добавлен systemd-tmpfiles конфиг `fic/src/scripts/tmpfiles/fic.conf`:
  `d /run/fic 0770 root fic -`.
- CMake install rules устанавливают `fic.conf` в `/usr/lib/tmpfiles.d`.
- ALT RPM packaging устанавливает `fic.conf` в `/usr/lib/tmpfiles.d` и вызывает
  `systemd-tmpfiles --create /usr/lib/tmpfiles.d/fic.conf` перед запуском
  сервисов.
- Debian 10/11/12 packaging делает то же самое для базового пакета `fic`.
- `fic/README.md` обновлен: пакетный runtime-каталог теперь описан как
  создаваемый через systemd-tmpfiles, а проверка в демоне остается fallback.
- На тестовой машине `172.31.100.26` (ALT Workstation K 11.3 p11) текущие
  unit/tmpfiles файлы применены вручную поверх установленных RPM, чтобы
  проверить runtime-поведение до пересборки пакетов.
- После ручного применения фикса на VM подтверждено:
  - `/run/fic` имеет `root:fic 770`;
  - `/run/fic/fic.sock` и `/run/fic/fic-device.sock` имеют `root:fic 660`;
  - одиночный рестарт `fic.service` больше не удаляет `fic-device.sock`;
  - одиночный рестарт `fic-device.service` больше не удаляет `fic.sock`;
  - `fic-cli status` и `fic-cli device root` отвечают после рестартов.
- На VM выполнен безопасный runtime-прогон device control:
  - `fic-udevadm-trigger` завершился с кодом 0;
  - дерево устройств заполнилось PCI-веткой под `/devices/pci0000:00`;
  - `device set 7 blocked` для подключенного PCI отклонен сообщением
    `operation would block an already connected device`;
  - `device set 7 allowed`, `ignore-hierarchy true/false`, `reset 7` прошли;
  - `device_attributes` для устройства 7 вернул udev/PCI атрибуты;
  - `fic-dick check-permanent` завершился с кодом 0, `lockstatus` остался
    `unlocked`.
- Исправлен graceful shutdown `fic-dick --daemon`: вместо блокирующего
  `accept()` цикл daemon теперь использует `select()` с таймаутом 1 секунда и
  затем вызывает `accept()` только при готовности server socket.
- На VM собранный `fic-dick` установлен вручную поверх RPM для проверки
  shutdown-fix. Старый бинарник сохранен как
  `/opt/fic/bin/fic-dick.before-sigterm-fix`.
- После установки нового бинарника на VM `systemctl restart fic-device.service`
  проходит без `State 'stop-sigterm' timed out` и без SIGKILL; оба сокета и IPC
  остаются рабочими.

## Измененные файлы

- `fic/src/scripts/service/fic.service`
- `fic/src/scripts/service/fic-device.service`
- `fic/src/scripts/tmpfiles/fic.conf`
- `fic/CMakeLists.txt`
- `fic/README.md`
- `packaging/rpm/build-fic-alt-p11-rpm.sh`
- `packaging/deb/build-fic-debian10-deb.sh`
- `packaging/deb/build-fic-debian11-deb.sh`
- `packaging/deb/build-fic-debian12-deb.sh`
- `fic-dick/src/core/DeviceControlDaemon.cpp`
- `docs/HANDOFF.md`

Изменения не закоммичены.

## Проверки

Выполнено:

```bash
bash -n packaging/rpm/build-fic-alt-p11-rpm.sh
bash -n packaging/deb/build-fic-debian10-deb.sh
bash -n packaging/deb/build-fic-debian11-deb.sh
bash -n packaging/deb/build-fic-debian12-deb.sh
cmake -S . -B /tmp/fic-runtime-tmpfiles-build
cmake --build /tmp/fic-runtime-tmpfiles-build -j2
cmake --build /tmp/fic-runtime-tmpfiles-build --target fic-dick -j2
git diff --check
```

Результат: проверки успешны. CMake configure прошел, были только существующие
deprecation warnings про `cmake_minimum_required`; полная сборка в
`/tmp/fic-runtime-tmpfiles-build` завершилась успешно.

Runtime-проверка на `172.31.100.26`:

```bash
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/fic.conf
sudo systemctl daemon-reload
sudo systemctl restart fic.service
sudo systemctl restart fic-device.service
sudo stat -c '%U %G %a %n' /run/fic /run/fic/fic.sock /run/fic/fic-device.sock
sudo /opt/fic/bin/fic-cli status
sudo /opt/fic/bin/fic-cli device root
sudo /opt/fic/bin/fic-udevadm-trigger
sudo /opt/fic/bin/fic-cli device children 5
sudo /opt/fic/bin/fic-cli device children 6
sudo /opt/fic/bin/fic-cli device set 7 blocked
sudo /opt/fic/bin/fic-cli device set 7 allowed
sudo /opt/fic/bin/fic-cli device ignore-hierarchy 7 true
sudo /opt/fic/bin/fic-cli device ignore-hierarchy 7 false
sudo /opt/fic/bin/fic-cli device reset 7
sudo /opt/fic/bin/fic-dick check-permanent
```

Дополнительно для проверки graceful shutdown на VM:

```bash
ssh admsys@172.31.100.26 "cat > /tmp/fic-dick.new" < /tmp/fic-runtime-tmpfiles-build/fic-dick/fic-dick
sudo cp -a /opt/fic/bin/fic-dick /opt/fic/bin/fic-dick.before-sigterm-fix
sudo install -o root -g fic -m 0770 /tmp/fic-dick.new /opt/fic/bin/fic-dick
sudo systemctl restart fic-device.service
sudo journalctl -u fic-device --since '2026-06-26 14:33:20' --no-pager
sudo stat -c '%U %G %a %n' /run/fic /run/fic/fic.sock /run/fic/fic-device.sock
sudo /opt/fic/bin/fic-cli status
sudo /opt/fic/bin/fic-cli device root
```

Не выполнялось:

- сборка deb/rpm пакетов;
- установка пересобранных обновленных пакетов на VM.

## Известные решения и ограничения

- `fic` и `fic-dick` продолжают запускаться как `root`; `Group=fic` намеренно
  не добавлялся, потому что доступ администраторов контролируется ownership и
  mode Unix-сокетов, а не primary group процесса.
- `/run/fic` не разносился на `/run/fic` и `/run/fic-device`, потому что оба
  сокета принадлежат одной административной зоне FIC и одной группе `fic`.
- Код демонов по-прежнему проверяет/создает runtime-каталог при старте. Это
  остается защитным fallback для разработки и непакетных запусков.
- Базовый пакет `fic` владеет tmpfiles-конфигом. `fic-dick` ставит
  `fic-device.service`, но сам не должен дублировать `/usr/lib/tmpfiles.d/fic.conf`.
- Во время VM-проверки обновленные unit/tmpfiles файлы были применены вручную,
  а не через новый RPM. RPM database по-прежнему содержит версию
  `0.1.0-1.altp11`.
- Во время VM-проверки новый `fic-dick` бинарник был установлен вручную, а не
  через RPM. RPM database по-прежнему содержит версию `0.1.0-1.altp11`.

## Что осталось

- Собрать новые пакеты и установить на тестовую ALT p11 VM вместо ручной правки
  unit/tmpfiles.
- После установки пакетов повторить:
  - `stat -c '%U %G %a %n' /run/fic /run/fic/fic.sock /run/fic/fic-device.sock`;
  - `systemctl restart fic.service`;
  - `systemctl restart fic-device.service`;
  - `systemctl restart fic.service fic-device.service`;
  - `fic-cli status`;
  - `fic-cli device root`.
- Убедиться, что рестарт одного сервиса больше не удаляет сокет другого.
- Убедиться, что пересобранный RPM с новым `fic-dick` также перезапускает
  `fic-device.service` без SIGKILL.

## Как продолжать в новой сессии

1. Прочитать `AGENTS.md` и этот файл.
2. Выполнить `git status --short` и сверить изменения.
3. Для продолжения этой задачи начинать с unit-файлов,
   `fic/src/scripts/tmpfiles/fic.conf`, CMake install rules и packaging scripts.
4. Не запускать реальные udev trigger, sysfs enforcement, lock/unlock или
   package install без явного запроса пользователя и подходящего тестового
   окружения.
