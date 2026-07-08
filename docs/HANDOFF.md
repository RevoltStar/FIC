# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-07-08.
- Ветка: `main`.
- Базовый commit: `97ee9cd`.
- Текущая задача: расширить QEMU/KVM e2e-проверки модуля "Контроль устройств"
  новыми типами устройств и матрицей enforcement/control-level сценариев.

## Сделано

- Добавлен runner `tests/device-control/test.sh`.
- Старый `tests/device-control/qemu_kvm_smoke.sh` оставлен как совместимый
  wrapper на `test.sh --type smoke`.
- Общая логика вынесена в `tests/device-control/lib/common.sh`.
- Категории тестов вынесены в:
  - `tests/device-control/suites/smoke.sh`;
  - `tests/device-control/suites/api.sh`;
  - `tests/device-control/suites/events.sh`;
  - `tests/device-control/suites/hierarchy.sh`;
  - `tests/device-control/suites/devices.sh`;
  - `tests/device-control/suites/enforcement.sh`;
  - `tests/device-control/suites/persistence.sh`;
  - `tests/device-control/suites/coldboot.sh`;
  - `tests/device-control/suites/race.sh`;
  - `tests/device-control/suites/security.sh`.
- Добавлен `tests/device-control/static_checks.py` для легких статических
  проверок инвариантов device-control кода и seed-базы без мутации VM.
- Скрипт рассчитан на VM с параметрами по умолчанию:
  - IP: `10.88.0.250`;
  - SSH-пользователь: `admsys`;
  - пароль SSH/sudo: значение из задачи, переопределяется через
    `FIC_VM_PASSWORD`.
- Домен libvirt можно задать через `FIC_VM_DOMAIN`; если он не задан, скрипт
  пытается найти домен по IP через `virsh domifaddr --source agent`,
  `--source lease`, а затем по MAC-адресу из `ip neigh` против
  `virsh domiflist`.
- URI libvirt задается через `FIC_LIBVIRT_URI`; по умолчанию используется
  `qemu:///system`.
- Состояние домена проверяется через `virsh list --state-running --name`,
  чтобы не зависеть от локализованного вывода `virsh domstate`, например
  `работает`.
- USB block-устройства в тестах ищутся по серийникам transient-дисков
  (`ID_SERIAL`, `ID_SERIAL_SHORT`, `SERIAL`), а имена `/dev/sdb` и `/dev/sdc`
  используются только как fallback, потому что target name при USB hotplug не
  гарантирует имя block-устройства внутри гостя.
- SSH запускается с `LogLevel=ERROR`, чтобы повторные подключения не зашумляли
  вывод предупреждениями known-host.
- Скрипт требует явный флаг запуска:
  `--yes-i-know-this-mutates-vm`.
- Новый формат запуска:

```bash
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type smoke
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type api
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type events
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type hierarchy
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type devices
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type enforcement
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type persistence
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type coldboot
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type race
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type security
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type all
```

- В сценарий включены проверки:
  - наличие host-зависимостей `sshpass`, `ssh`, `virsh`, `qemu-img`,
    `python3`, `ip`, `awk`;
  - доступность гостя по SSH;
  - наличие и состояние libvirt-домена;
  - готовность `/opt/fic/bin/fic-cli`, `/opt/fic/bin/fic-dick` и
    `fic-dick wait-daemon`;
  - ответ `status` от `/run/fic/fic-device.sock`;
  - чтение `device_root`;
  - видимость PCI-устройств после `udevadm trigger --subsystem-match=pci`;
  - live-подключение virtio block-диска и появление block-устройства в дереве;
  - наличие события `connect`;
  - live-отключение virtio block-диска и сохранение записи в disconnected
    history;
  - отсутствие отключенного virtio block-диска в текущем дереве без истории;
  - установка и сброс явного правила `allowed` на отключенном устройстве;
  - отказ назначить `permanent` отсутствующему устройству;
  - удаление отключенного исторического поддерева;
  - подключение USB storage при выключенной DC-политике и проверка `allowed`;
  - проверка USB-атрибутов и серийника transient-диска;
  - отказ невалидного `control_level`;
  - назначение `permanent` подключенному устройству и последующий сброс без
    вызова глобального `device_check_permanent`;
  - включение `DC/block_usb_storage`, подключение нового USB storage и проверка
    `blocked` с источником `dc:block_usb_storage`;
  - проверка, что заблокированное USB storage после enforcement не остается
    подключенным;
  - наличие события `block` для заблокированного USB storage;
  - лимит `device_events`;
  - фильтрация глобальных `block` событий;
  - порядок `connect` перед `block` для заблокированного USB;
  - отказ удаления подключенного устройства и root-узла;
  - отказ непривилегированного `udev_event` либо отказ доступа Unix-сокета;
  - отказ битого JSON;
  - сохранение CLI текста ошибки демона.
- Добавлены расширенные suite-ы:
  - `devices`: live hotplug USB HID keyboard, USB tablet/input, virtio RNG как
    PCI mock, CD-ROM, virtio-net и virtio serial channel;
  - `enforcement`: explicit `allowed`, explicit `blocked` с повторным hotplug и
    событием `block`, `ignored` на родителе поверх blocked-ребенка,
    `permanent` на подключенном устройстве с `udevadm trigger --action=change`,
    наследование `allowed` от parent и `ignored` от grandparent, отказ ставить
    `blocked` на уже подключенное устройство или его подключенного parent,
    reset parent с проявлением явного child `blocked`;
  - `persistence`: сохранение explicit control, disconnected blocked rule,
    истории событий и состояния `DC/block_usb_storage` после рестарта
    `fic-device.service`/`fic.service`;
  - `coldboot`: enforcement для USB storage, заранее добавленного в persistent
    libvirt domain config и присутствующего уже при старте VM; suite делает
    reboot гостя и проверяет как DC-policy block, так и explicit device block;
  - `race`: параллельные IPC-чтения внутри гостя, быстрые virtio attach/detach
    циклы и hotplug при переключении `DC/block_usb_storage`.
- Runner кладет временный Python IPC-helper в гостя (`/tmp/fic-dc-ipc.py`),
  подключает transient qcow2-диски через `virsh attach-disk --live`, а в
  `trap` пытается отключить тестовые диски, удалить helper и восстановить
  исходное значение `DC/block_usb_storage`.
- В `trap` добавлен best-effort сброс control-level для тестовых устройств перед
  detach, чтобы не оставить transient-диск в `permanent` при падении середины
  сценария.
- Для cleanup remote helper получил режим `reset-path`: он сбрасывает
  control-level у тестового устройства и его ancestor-цепочки до root, не
  трогая сам root. Это снижает риск оставить `ignored`/`permanent` на
  промежуточном родителе после аварийного падения расширенных inheritance-
  тестов.
- После первого пользовательского `--type all` прогона исправлены проблемы
  изоляции suite-ов:
  - Ctrl-C теперь прерывает runner и запускает cleanup, а не продолжает
    следующие тесты;
  - transient qcow2 пересоздаются через общий `create_test_image()`, который
    удаляет старый файл перед `qemu-img create`;
  - allowed USB fixtures явно выключают `DC/block_usb_storage`, даже если
    устройство уже подключено после предыдущего suite;
  - virtio fixture в events-suite больше не пересоздает образ, если диск уже
    подключен;
  - порядок `connect`/`block` проверяется после сортировки событий по
    `created_at` и `id`, а не по порядку ответа API.
- После второго пользовательского `--type all` прогона исправлены оставшиеся
  протечки control-level между запусками:
  - `reset_device_from_response()` теперь сбрасывает не только само тестовое
    устройство, но и его непосредственного родителя;
  - `prepare_environment()` запускает `reset_test_device_controls()` после
    сохранения исходной DC-политики, чтобы новый прогон начинался без
    оставшихся `ignored`/`permanent` правил на тестовых устройствах;
  - allowed USB fixtures сбрасывают test device + parent как для уже
    подключенного устройства, так и сразу после нового hotplug;
  - blocked USB fixture в events-suite всегда пересоздается после reset/detach,
    чтобы не принять stale connected/ignored устройство за готовое.
- После этих исправлений пользовательский полный прогон новой suite-структуры
  завершился успешно: `Summary: 35 tests, 0 failed`.
- После добавления `devices`/`enforcement` пользовательские запуски этих
  категорий сначала завершались только preflight-ом (`Summary: 4 tests,
  0 failed`): `prepare_environment` возвращал статус best-effort
  `reset_test_device_controls`, который становился `1`, если новый CD-ROM target
  еще не встречался в БД. Исправлено: `reset_test_device_controls` теперь всегда
  возвращает `0`, а `run_suite_file` явно помечает suite как failed, если после
  вызова не запустился ни один тест.
- Первый реальный пользовательский прогон `--type devices` показал, что
  установленное udev-rule FIC обрабатывает `usb`, `usbmisc`, `pci` и `block`,
  но не доставляет события `input`, `net`, `tty` или `virtio-ports` в
  `fic-dick`. Из-за этого USB HID, PCI mock и CD-ROM проходили, а USB tablet
  input, virtio-net и virtio serial падали на ожидании роста unsupported
  subsystem. Исправлено в тестах: для таких QEMU hotplug устройств suite ищет
  новый sysfs-объект и root helper-ом отправляет `udev_event` напрямую в
  device daemon через новый режим remote helper `udev-from-sysfs`. Это
  проверяет collector/API для этих типов, не утверждая, что текущее
  установленное udev-rule уже ловит их автоматически.
- Пользовательский `--type all` после исправления `udev-from-sysfs` завершился
  `Summary: 47 tests, 1 failed`: падал только `virtio serial channel is
  recorded`. Отдельная диагностика показала две причины в тестовой обвязке:
  предыдущий неудачный прогон оставил live-channel `fic.dc.serial.0` в домене
  как alias `channel2`, потому что detach по неполному XML не снял устройство;
  а сам тест искал порт только в `/sys/bus/virtio-ports/devices`, тогда как в
  этой VM реальные порты находятся под
  `/sys/devices/.../virtio-ports/vport*`. Исправлено: cleanup снимает serial
  fixture через `virsh detach-device-alias`, alias ищется по live XML, а тест
  ищет `vport*` по regex в `/sys/devices` и проверяет запись в DB по точному
  `DEVPATH`, а не по росту счетчика subsystem. Оставшийся `channel2` был
  вручную отключен; после исправлений одиночный serial-тест прошел, и live XML
  больше не содержал `fic.dc.serial.0`.
- После этого пользовательский полный прогон показал падение
  `disconnected device subtree can be deleted`: удаление отключенного
  устройства возвращало `ok=true`, но test post-check снова искал любое
  историческое устройство с `DEVNAME=/dev/vdb`. В накопленной истории могут
  оставаться другие записи от прошлых прогонов с тем же `DEVNAME`, поэтому
  проверка была шире, чем действие API. Исправлено: после `device_delete` тест
  проверяет, что конкретный удаленный `device_id` больше не читается через
  `device_get` и возвращает `device not found`.
- Добавлены новые suite-ы по итогам оценки достаточности покрытия:
  `persistence`, `coldboot` и `race`; runner `test.sh` теперь принимает эти
  значения в `--type`, а `--type all` запускает их вместе с остальными. Для
  `coldboot` добавлены helper-ы `attach_disk_config`, `detach_disk_config`,
  `reboot_guest` и проверка смены `/proc/sys/kernel/random/boot_id`, чтобы SSH
  readiness не принималась за факт завершенного reboot. Cleanup теперь
  best-effort снимает тестовые диски и из live, и из persistent domain config.
- Первый вариант `race` создавал 20 параллельных SSH-сессий и падал на
  `kex_exchange_identification: Connection reset by peer`; это был лимит SSH, а
  не daemon/socket. Исправлено: remote helper получил режим `stress-read`,
  который создает параллельные IPC-чтения внутри гостя через Unix socket одним
  SSH-вызовом.
- Два новых negative enforcement-теста сначала были сформулированы как
  `blocked parent` сценарии, но модуль корректно отказывает ставить `blocked`
  на уже подключенное устройство/parent с сообщением
  `operation would block an already connected device`. Тесты переписаны на
  проверку этого отказа; расширенный `--type enforcement` после правки прошел.

## Измененные файлы

- `tests/device-control/qemu_kvm_smoke.sh`
- `tests/device-control/test.sh`
- `tests/device-control/lib/common.sh`
- `tests/device-control/static_checks.py`
- `tests/device-control/suites/smoke.sh`
- `tests/device-control/suites/api.sh`
- `tests/device-control/suites/events.sh`
- `tests/device-control/suites/hierarchy.sh`
- `tests/device-control/suites/devices.sh`
- `tests/device-control/suites/enforcement.sh`
- `tests/device-control/suites/persistence.sh`
- `tests/device-control/suites/coldboot.sh`
- `tests/device-control/suites/race.sh`
- `tests/device-control/suites/security.sh`
- `docs/HANDOFF.md`

## Проверки

Выполнено:

```bash
bash -n tests/device-control/qemu_kvm_smoke.sh
bash -n tests/device-control/lib/common.sh
bash -n tests/device-control/test.sh
bash -n tests/device-control/suites/smoke.sh
bash -n tests/device-control/suites/api.sh
bash -n tests/device-control/suites/events.sh
bash -n tests/device-control/suites/hierarchy.sh
bash -n tests/device-control/suites/devices.sh
bash -n tests/device-control/suites/enforcement.sh
bash -n tests/device-control/suites/persistence.sh
bash -n tests/device-control/suites/coldboot.sh
bash -n tests/device-control/suites/race.sh
bash -n tests/device-control/suites/security.sh
python3 tests/device-control/static_checks.py .
tests/device-control/qemu_kvm_smoke.sh --help
tests/device-control/test.sh --help
# Пользовательский прогон на VM:
tests/device-control/qemu_kvm_smoke.sh --yes-i-know-this-mutates-vm
# Пользовательский прогон новой suite-структуры:
tests/device-control/test.sh --yes-i-know-this-mutates-vm --type all
```

Результат: синтаксис Bash корректен, справка скрипта выводится. Проверка
повторялась после добавления `FIC_LIBVIRT_URI`, fallback-детекта домена по MAC
и исправления форматирования SSH-preflight вывода. Также проверено после
перевода проверки состояния домена на `virsh list --state-running --name` и
после перевода USB-поиска с фиксированных `/dev/sdX` на серийники тестовых
дисков. После разбиения на runner/suite-файлы агентом выполнены только
`bash -n` для всех новых shell-файлов и `--help` для runner/wrapper.
Пользовательский полный прогон монолитной расширенной версии до разбиения
завершился результатом `Summary: 21 tests, 0 failed`. Полные VM-прогоны новой
suite-структуры до последних исправлений дважды завершались
`Summary: 35 tests, 5 failed`: сначала из-за Ctrl-C/изоляции fixture-ов, затем
из-за оставшихся `ignored`/`permanent` правил на тестовом USB-устройстве или
его родителе. После последних исправлений агентом повторно выполнены
`bash -n` для shell-файлов, `python3 tests/device-control/static_checks.py .`
и `test.sh --help`. Пользовательский полный VM-прогон исправленной
suite-структуры до добавления `devices`/`enforcement` завершился результатом
`Summary: 35 tests, 0 failed`. После добавления `devices`/`enforcement`
агентом выполнены `bash -n` для всех shell-файлов,
`python3 tests/device-control/static_checks.py .` и `test.sh --help`. После
исправления раннего выхода на best-effort cleanup эти проверки повторены; новый
полный VM-прогон еще не выполнялся.
Пользовательский прогон `--type enforcement` после добавления новых тестов
завершился успешно: `Summary: 10 tests, 0 failed`. Пользовательский прогон
`--type devices` до исправления `udev-from-sysfs` завершился результатом
`Summary: 10 tests, 3 failed` на `input`, `net` и `tty/virtio-ports`.
Пользовательский `--type all` после этого завершился `Summary: 47 tests,
1 failed` на `virtio serial channel is recorded`. Агентом выполнена отдельная
диагностика и одиночный прогон serial-теста после исправлений:
`Summary: 5 tests, 0 failed`; затем проверено, что live XML домена больше не
содержит `fic.dc.serial.0`. После исправления проверки удаления агентом
выполнены `bash -n tests/device-control/suites/api.sh`,
`python3 tests/device-control/static_checks.py .` и одиночный VM-прогон
упавшего API-теста; результат: `Summary: 5 tests, 0 failed`.
После добавления `persistence`/`coldboot`/`race` агентом выполнены:
`bash -n` для `test.sh`, `lib/common.sh` и всех `suites/*.sh`,
`python3 tests/device-control/static_checks.py .`, `test.sh --help`, а также
отдельные VM-прогоны:

```bash
./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type persistence
# Summary: 8 tests, 0 failed

./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type race
# первый прогон: Summary: 7 tests, 1 failed из-за параллельного SSH;
# после stress-read исправления: Summary: 7 tests, 0 failed

./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type enforcement
# первый прогон после новых negative tests: Summary: 13 tests, 2 failed;
# после переписывания на ожидаемый отказ connected block: Summary: 13 tests, 0 failed

./tests/device-control/test.sh --yes-i-know-this-mutates-vm --type coldboot
# Summary: 6 tests, 0 failed
```

Не выполнялось агентом напрямую:

- полный VM-прогон новой suite-структуры через `test.sh --type ...`;
- повторный VM-прогон `devices` после исправления serial/virtio-ports;
- повторный VM-прогон `devices` после исправления `udev-from-sysfs`;
- полный `--type all` после исправления serial-channel теста;
- полный `--type all` после исправления post-check удаления disconnected
  virtio-устройства;
- полный `--type all` после добавления `persistence`, `coldboot` и `race`;
- подключение или отключение всех устройств из полного сценария одним
  прогоном; агентом выполнялись отдельные suite-ы `persistence`, `race`,
  `enforcement`, `coldboot` и одиночный API-тест удаления disconnected virtio
  fixture;
- сборка CMake-целей.

Полные `--type all` запуски выполнялись пользователем, а не агентом. Отдельные
suite-запуски агентом тоже меняли состояние виртуальной машины: подключали и
отключали live/config-устройства, создавали временные qcow2-образы, временно
меняли `DC/block_usb_storage`, рестартовали `fic.service`/`fic-device.service`
и для `coldboot` перезагружали гостя; итоговый trap должен был вернуть
исходное состояние политики и отключить transient-диски.

## Решения и риски

- Скрипт использует libvirt/`virsh` как управляющий слой QEMU/KVM. Если VM
  запущена не через libvirt, `domifaddr` не знает IP и MAC fallback не сработал,
  нужно передать `FIC_VM_DOMAIN`. Если нужен не `qemu:///system`, нужно передать
  `FIC_LIBVIRT_URI`.
- Для USB storage используется `virsh attach-disk --targetbus usb`; VM должна
  поддерживать live hotplug USB storage. Если в домене нет подходящего USB-
  контроллера, соответствующие тесты упадут на этапе attach.
- Для `devices` используются дополнительные live hotplug-устройства: USB input,
  virtio RNG, CD-ROM, virtio-net и virtio serial channel. Если конкретная VM не
  поддерживает live hotplug соответствующего типа, упадет только этот suite.
- Для virtio-net suite скрипт пытается подключить новую NIC к тому же libvirt
  `type/source`, что и первая существующая NIC домена. В нестандартных сетевых
  конфигурациях можно задать `FIC_VIRTIO_NET_TYPE` и `FIC_VIRTIO_NET_SOURCE`.
- Virtio block-тест по-прежнему ищет устройство по `DEVNAME` (`/dev/vdb`).
  USB-тесты сначала ищут устройство по серийнику transient-диска и только затем
  fallback по `DEVNAME`. Если target-имена заняты, их нужно переопределить
  через `FIC_VIRTIO_TARGET`, `FIC_USB_ALLOWED_TARGET`,
  `FIC_USB_BLOCKED_TARGET` и `FIC_CDROM_TARGET`.
- Блокирующий USB-тест ожидает, что `fic-dick` успеет записать устройство и
  событие `block` до того, как enforcement деавторизует/удалит устройство.
- `coldboot` suite добавляет тестовый диск в persistent libvirt config и
  перезагружает гостя; cleanup снимает config-attachment best-effort, но при
  аварийном обрыве стоит проверить `virsh dumpxml`/`detach-disk --config` для
  target-ов `FIC_USB_ALLOWED_TARGET` и `FIC_USB_BLOCKED_TARGET`.
- Пароль задан дефолтом из задачи для удобства лабораторного запуска; для
  других окружений лучше передавать его через переменную окружения.
