# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-27.
- Ветка: `main`.
- Базовый commit: `f167f88` (`Ранний fic-dick udev больше не считается ошибкой...`).
- Текущая задача: исправить обращение GUI за атрибутами устройств в неправильный
  Unix socket.

## Контекст

- На тестовой машине `172.17.1.105` после подключения USB-флешки дерево
  устройств обновилось корректно: появились `usb1/1-2`, `1-2:1.0`,
  virtual SCSI/block-промежуточные узлы, `sdb`, `sdb1`, `sdb2`.
- В journal при кликах GUI по устройствам появлялось:
  `Failed to load device attributes: "device tree API is served by fic-dick on /run/fic/fic-device.sock"`.
- Причина: `DeviceAttributeList::showDeviceAttributes()` отправлял команду
  `device_attributes` через `fic::ipc::Client()` без явного socket path.
  Такой клиент использует основной daemon socket `/run/fic/fic.sock`.
- Device tree API обслуживается `fic-dick` на `/run/fic/fic-device.sock`.
  `DeviceTree` и `fic-cli` уже использовали правильный socket.

## Сделано в текущем рабочем дереве

- В `fic-gui/src/DeviceAttributeList.cpp` вызов:

```cpp
fic::ipc::Client().request(...)
```

заменен на:

```cpp
fic::ipc::Client(fic::ipc::DEFAULT_DEVICE_SOCKET_PATH).request(...)
```

- После правки `DeviceAttributeList` использует тот же device socket, что и
  `DeviceTree`.

## Измененные файлы

- `fic-gui/src/DeviceAttributeList.cpp`
- `docs/HANDOFF.md`

## Проверки

Выполнено:

```bash
git status --short
git diff --check
rg -n "fic::ipc::Client\\(\\)\\.request\\(\\{\\{\\\"command\\\", \\\"device_|device_attributes" fic-gui/src -g '*.[ch]pp' -g '*.h'
cmake -S . -B /tmp/fic-build-check
cmake --build /tmp/fic-build-check --target fic-gui -j2
```

`fic-gui` успешно собран в `/tmp/fic-build-check`.

Не выполнялось:

- сборка deb/rpm пакетов;
- установка пакета на тестовую машину;
- запуск GUI/runtime-проверка на `172.17.1.105`.

## Что проверить после установки

1. Открыть `fic-gui`.
2. Кликнуть по устройствам, включая USB-флешку (`sdb`, `sdb1`, `sdb2`).
3. В панели атрибутов должны отображаться udev-атрибуты устройства.
4. В journal не должно быть ошибки:
   `device tree API is served by fic-dick on /run/fic/fic-device.sock`.

## Решения и риски

- Исправление точечное: меняется только socket для команды `device_attributes`
  в `DeviceAttributeList`.
- Остальные обращения GUI к обычным политикам и логам оставлены на основном
  daemon socket `/run/fic/fic.sock`.
