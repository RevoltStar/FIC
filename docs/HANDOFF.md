# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-28.
- Ветка: `main`.
- Базовый commit: `9dbe1c8`.
- Текущая задача: реализовать согласованные исправления по аудиту компонента
  «Контроль устройств».

## Что было решено по аудиту

- DC-01 не изменялся: ожидаемое поведение состоит в том, что
  `block_usb_storage` и похожие DC-настройки влияют только на подключаемые или
  переподключаемые устройства, но не отключают уже подключенные устройства.
- DC-05 не изменялся: текущая модель контроля устройств завязана на
  последовательном построении дерева, поэтому тайм-ауты/параллелизм DB/IPC пока
  не переделывались.
- DC-02, DC-03, DC-04, DC-06, DC-07, DC-08, DC-09, DC-10, DC-11, DC-12, DC-13
  и DC-14 реализованы.

## Сделано

- `permanent`-проверка теперь оценивает обязательное устройство по стабильной
  идентичности `device_hash + subsystem`, а не по одному историческому
  occurrence.
- Remove-событие проверяет permanent-нарушения по всему отключенному поддереву.
- `udev_event` через device socket теперь принимается только от root peer
  credentials; devpath дополнительно нормализуется под `/sys/devices`.
- Запись udev-устройства и его атрибутов выполняется транзакционно; ошибка
  любого атрибута приводит к rollback.
- `allow` enforcement больше не проглатывает ошибку записи в USB `authorized`;
  результат записывается в `device_events`.
- Sysfs block/allow/remove операции получили короткие retry-попытки.
- `/devices/virtual/block/...` больше не отбрасывается общим udev-фильтром.
- Coldplug service `fic_get_device_udev_info.service` запускается сразу в
  package postinst, где есть `systemctl`.
- Mutating device IPC-команды пишут audit-log с peer uid/gid/pid, командой и
  результатом.
- Runtime-миграции SQLite удалены из `DB::initializeDatabase()`.
- Seed DB `fic/src/scripts/db/devices.db` обновлена: таблица `devices` содержит
  `control_explicit`.
- Device daemon больше не делает безусловный `unlink()` существующего socket:
  перед удалением stale socket он пробует обнаружить уже работающий daemon.
- Добавлен CTest `device_control_static_checks`.
- Обновлен `fic-dick/README.md`.

## Измененные файлы

- `CMakeLists.txt`
- `tests/CMakeLists.txt`
- `tests/device-control/static_checks.py`
- `fic-common/fic-device-db/src/DB.cpp`
- `fic-dick/README.md`
- `fic-dick/src/core/DeviceControlDaemon.cpp`
- `fic-dick/src/core/InfoCollector.cpp`
- `fic-dick/src/modules/UDEVInfoCollector.cpp`
- `fic/src/scripts/db/devices.db`
- `packaging/deb/build-fic-debian10-deb.sh`
- `packaging/deb/build-fic-debian11-deb.sh`
- `packaging/deb/build-fic-debian12-deb.sh`
- `packaging/rpm/build-fic-alt-p11-rpm.sh`
- `docs/HANDOFF.md`

## Проверки

Выполнено:

```bash
git diff --check
python3 tests/device-control/static_checks.py .
cmake -S . -B /tmp/fic-build-check
cmake --build /tmp/fic-build-check --target fic-dick -j2
cmake --build /tmp/fic-build-check --target fic-cli -j2
cmake --build /tmp/fic-build-check --target fic-gui -j2
cmake --build /tmp/fic-build-check -j2
ctest --test-dir /tmp/fic-build-check --output-on-failure
```

Результат: все перечисленные проверки успешно выполнены.

Замечание: при сборке `fic-gui` снова появлялось предупреждение GNU make
`jobserver mkfifo: /tmp/GMfifo3: File exists`, но цель собралась успешно.

Не выполнялось:

- runtime-запуск `fic-dick --daemon`;
- реальные udev trigger, policy apply, lock/unlock, device mutation;
- запись в `/opt/fic`;
- сборка deb/rpm пакетов.

## Риски и что проверить в runtime

- Retry для sysfs сейчас синхронный и короткий; полноценная persistent queue не
  добавлялась, потому что DC-05 оставлен без изменения.
- После удаления runtime-миграций старая установленная БД с прежней схемой не
  будет автоматически обновляться. Для текущей стадии разработки это намеренно;
  новая установка должна использовать обновленную seed DB.
- Нужно проверить на тестовой машине:
  - подключение USB/block/PCI через udev;
  - `fic-dick check-permanent` при переносе permanent-устройства в другой порт;
  - remove родителя, у которого есть permanent-потомок;
  - отказ не-root клиента на ручной `udev_event`;
  - появление device audit-log для `device_update_*`, `device_delete`,
    `device_check_permanent`;
  - immediate coldplug после установки пакета.
