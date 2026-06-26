# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-26.
- Ветка: `main`.
- Базовый commit: `255c9b1` (`Исправляем гонку для udev-устройств, добавляем fallback для статических устройств (если нет хэша для утилит)`).
- Текущая задача: убрать причины долгой загрузки после установки пакета и
  перенести выбор udev-подсистем из `UDEVInfoCollector` в udev-правило.

## Контекст диагностики

- На машине `172.17.1.105` загрузка задерживалась примерно до 1m36s.
- В журнале были массовые запуски `fic-dick udev`, которые ждали отсутствующий
  `/run/fic/fic-device.sock` и повторяли подключение.
- Установленное udev-правило было слишком широким:
  `ACTION=="add|change|remove", SUBSYSTEM!="", ...`.
- Это давало много ранних coldplug-событий до готовности `fic-device.service`.
  После commit `255c9b1` плановый `fic-udevadm-trigger` уже ждет готовности
  daemon через `fic-dick wait-daemon`, поэтому retry внутри каждого udev helper
  стал вредным.
- В логах также встречалось:
  `device was updated but cannot be found in database`. Причина: при повторном
  обнаружении устройства по `hash + subsystem + parent` обновлялся только
  `boot_id`, но не актуальный `devpath`, а обработчик затем искал устройство по
  новому `devpath + subsystem + boot_id`.

## Сделано в текущем рабочем дереве

- `fic/src/scripts/udev/99-fic-devices.rules` теперь запускает `fic-dick udev`
  только для `usb`, `pci` и `block`.
- Из `UDEVInfoCollector` полностью удален `EXCLUDED_SUBSYSTEM` и метод
  `check_excluded_subsystem`.
- `handle_udev_event` больше не фильтрует подсистемы внутри daemon; остается
  только проверка физического `DEVPATH`.
- В `check_devpath` проверка `nullptr` теперь выполняется до построения
  `std::string(devpath)`.
- Из `fic-dick udev` удален retry подключения к device socket. Helper делает
  одну IPC-попытку и быстро завершается, если daemon еще не готов.
- При обновлении уже известного устройства по `hash + subsystem + parent`
  теперь обновляются `devpath`, `subsystem`, `device_type`, `parent_id`,
  `boot_id` и `notes`, чтобы последующий поиск по текущему `devpath` находил
  запись.
- Обновлены `fic-dick/README.md` и `docs/architecture-diagrams.md` под новую
  модель: список подсистем задается udev-правилом, а не кодом коллектора.

## Измененные файлы

- `fic/src/scripts/udev/99-fic-devices.rules`
- `fic-dick/src/core/DeviceControlDaemon.cpp`
- `fic-dick/src/modules/UDEVInfoCollector.cpp`
- `fic-dick/src/modules/UDEVInfoCollector.h`
- `fic-dick/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Проверки

Выполнено после правок:

```bash
git status --short
rg -n "EXCLUDED_SUBSYSTEM|check_excluded_subsystem|is_retryable_device_socket_error|maxAttempts|udev event ignored: excluded subsystem" fic-dick/src fic/src/scripts docs/architecture-diagrams.md fic-dick/README.md
sh -n fic/src/scripts/service/fic-udevadm-trigger
git diff --check
```

`rg` не нашел старых символов и сообщений в коде, udev/service-скриптах,
README и архитектурной диаграмме.

Не выполнялось:

- сборка CMake;
- сборка deb/rpm пакетов;
- установка пакетов;
- runtime-рестарты сервисов на тестовой машине;
- повторный `udevadm trigger`.

## Что проверить после пересборки и установки пакетов

1. Перезагрузить тестовую машину.
2. Проверить:
   - `systemctl status fic.service fic-device.service fic_get_device_udev_info.service fic_get_device_info.service`;
   - `systemd-analyze blame`;
   - `journalctl -b -u systemd-udevd --no-pager | grep fic-dick`;
   - `fic-cli status`;
   - `fic-cli device root`;
   - `fic-cli device children 5`;
   - `fic-cli device children 6`.
3. В journal не должно быть серии ошибок подключения к
   `/run/fic/fic-device.sock` с паузами около 5 секунд.
4. В дереве устройств должны появляться дочерние узлы для `/devices/pci0000:00`
   после boot-time `fic-udevadm-trigger`.

## Решения и риски

- Retry убран именно из `fic-dick udev`, потому что udev helper должен быть
  короткоживущим. Ожидание готовности daemon оставлено в контролируемом месте:
  `fic-udevadm-trigger` перед `udevadm trigger`.
- Фильтрация подсистем намеренно перенесена в
  `fic/src/scripts/udev/99-fic-devices.rules`. Если понадобится расширить
  контроль на другую подсистему, менять нужно правило, а не
  `UDEVInfoCollector`.
- Базовый `UDEVInfoCollector` и generic branch в
  `create_collector_for_subsystem` оставлены для прямых IPC/ручных сценариев,
  но пакетное udev-правило до них для сторонних подсистем не доходит.
