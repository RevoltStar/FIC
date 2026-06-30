# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-29.
- Ветка: `main`.
- Базовый commit: `4afc8f4`.
- Текущая задача: сделать первый практический шаг к function-level контролю
  USB-МФУ: различать USB-устройство, его интерфейсы и USB printer node
  `/dev/usb/lp*`, чтобы администратор мог отдельно видеть функцию печати и
  функцию сканирования.

## Контекст

- На тестовой машине Epson L3250 появился в live udev как USB composite device:
  физическое устройство `/usb1/1-2`, интерфейсы `1-2:1.0`, `1-2:1.1`,
  `1-2:1.2` и printer node `/dev/usb/lp0` в subsystem `usbmisc`.
- До этой задачи `USBInfoCollector` идентифицировал USB слишком грубо:
  `ID_MODEL_ID`, `ID_SERIAL`, `ID_VENDOR_ID`, `TYPE`. Для `usb_interface` у
  Epson `TYPE` был одинаковым/неинформативным, поэтому разные функции МФУ могли
  схлопываться в один узел.
- Udev-правило FIC ловило только `usb`, `pci`, `block`, поэтому `usbmisc/lp0`
  вообще не попадал в БД.
- GUI называл USB-узлы в основном по классу, поэтому `EPSON L3250` был виден в
  атрибутах, но не был очевиден в дереве.

## Сделано

- `USBInfoCollector` теперь выбирает поля идентификации по `DEVTYPE`:
  - `usb_device`: `DEVTYPE`, `ID_VENDOR_ID`, `ID_MODEL_ID`, `ID_SERIAL`,
    `PRODUCT`, `TYPE`, `ID_USB_INTERFACES`;
  - `usb_interface`: `DEVTYPE`, `PRODUCT`, `INTERFACE`, `TYPE`, `MODALIAS`;
  - fallback: `DEVTYPE`, `PRODUCT`, `TYPE`, `MODALIAS`, `DEVPATH`.
- Для USB-интерфейсов добавляются атрибуты:
  - `FIC_USB_IDENTITY_SCOPE=interface`;
  - `FIC_USB_FUNCTION=printer|scanner|storage|hid|vendor-specific`, если
    функцию можно вывести из `INTERFACE`.
- В udev-правило добавлен subsystem `usbmisc`, чтобы устройства вроде
  `/dev/usb/lp0` попадали в дерево.
- `fic-dick --daemon` и legacy-фабрика в `fic-dick/src/main.cpp` создают для
  `usbmisc` базовый `UDEVInfoCollector` с полями `DEVNAME`, `DEVPATH`,
  `MAJOR`, `MINOR`.
- GUI теперь показывает USB-узлы человеко-читаемо:
  - `USB устройство [EPSON L3250_Series] [...]`;
  - `USB интерфейс [Принтер] [...]`;
  - `USB печать [/dev/usb/lp0]`.
- Быстрый фильтр GUI `USB` теперь включает `usbmisc`.
- Обновлены `fic-dick/README.md` и `docs/architecture-diagrams.md`.

## Измененные файлы

- `fic-dick/src/modules/USBInfoCollector.h`
- `fic-dick/src/modules/USBInfoCollector.cpp`
- `fic-dick/src/core/DeviceControlDaemon.cpp`
- `fic-dick/src/main.cpp`
- `fic-gui/src/DeviceTree.cpp`
- `fic/src/scripts/udev/99-fic-devices.rules`
- `fic-dick/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Проверки

Выполнено:

```bash
git diff --check
cmake -S . -B /tmp/fic-build-check
cmake --build /tmp/fic-build-check --target fic-dick -j2
cmake --build /tmp/fic-build-check --target fic-gui -j2
```

Результат: `fic-dick` и `fic-gui` успешно собраны.

Замечание: при параллельной сборке в одном build-dir `gmake` один раз вывел
`jobserver mkfifo: /tmp/GMfifo3: File exists`, но цель `fic-gui` завершилась
успешно.

Не выполнялось:

- сборка deb/rpm пакетов;
- установка пакета на тестовую машину;
- runtime-запуск `fic-gui`;
- udev trigger/retrigger;
- реальные операции policy apply, lock/unlock или запись в `/opt/fic`.

## Что проверить после установки

1. Перезагрузить машину или выполнить контролируемый udev-retrigger штатным
   механизмом пакета/сервиса.
2. Подключить Epson L3250.
3. Проверить в GUI:
   - физический Epson должен быть заметен по vendor/model;
   - интерфейс печати должен отображаться отдельно как `USB интерфейс [Принтер]`;
   - `/dev/usb/lp0` должен появиться как `USB печать [/dev/usb/lp0]`, если
     kernel создал `usbmisc/lp0`.
4. Проверить CLI:

```bash
fic-cli device children <id родителя usb1>
fic-cli device children <id Epson>
```

## Решения и риски

- Схему БД не меняли и миграцию старых записей не делали. Существующие записи
  могут остаться схлопнутыми до нового udev-события или повторного сбора.
- Это не полный universal print/scanner enforcement. Для USB-печати отдельный
  узел `/dev/usb/lp0` теперь виден, а существующий USB enforcement ищет
  ближайший sysfs `authorized` вверх по дереву. Но CUPS/IPP/eSCL/network
  backends могут потребовать отдельного слоя контроля.
- Правило “не блокировать активное устройство” сохраняется: назначение
  `blocked` на уже подключенную функцию всё ещё должно отклоняться daemon API.
- Если parent USB device заблокировать целиком, дочерние функции физически не
  появятся. Для сценария “запретить печать, разрешить сканирование” нужно
  настраивать правило на printer interface или `/dev/usb/lp0`, а не на весь
  Epson.
