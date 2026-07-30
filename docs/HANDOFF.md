# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-30.
- Ветка: `main`.
- Базовый commit: `5f3d5f2`.
- Текущая задача: не перестраивать дерево устройств каждые пять секунд, если
  данные устройств не изменились.
- Реализация и локальная проверка завершены, изменения не зафиксированы commit.

## Сделано

- В схему SQLite добавлена служебная таблица `device_tree_state` с
  целочисленной ревизией.
- Девять триггеров увеличивают ревизию при `INSERT`/`UPDATE`/`DELETE` таблиц
  `devices`, `device_attributes` и `device_events`. Триггеры добавлены и в
  `DB::initializeDatabase()`, и в seed-базу.
- Общий DB-слой предоставляет `DB::getDeviceTreeRevision()`.
- `fic-dick --daemon` обслуживает read-only команду
  `device_tree_revision`, возвращающую `revision`.
- GUI по-прежнему использует таймер 5 секунд, но на каждом тике запрашивает
  только ревизию. Полное перестроение выполняется лишь при изменившемся
  значении; первая успешная загрузка запоминает ревизию до чтения дерева, чтобы
  не пропустить конкурентное изменение.
- В `fic-cli` добавлена диагностическая команда `device revision`.
- Добавлены unit/static/smoke-проверки и обновлена документация API и
  архитектуры.

## Измененные файлы

- `fic-common/fic-device-db/include/fic/device-db/DB.h`
- `fic-common/fic-device-db/src/DB.cpp`
- `fic-dick/src/core/DeviceControlDaemon.cpp`
- `fic-gui/src/DeviceTree.{h,cpp}`
- `fic-cli/src/main.cpp`
- `fic/src/scripts/db/devices.db`
- `tests/device-control/DeviceTreeRevisionTests.cpp`
- `tests/device-control/static_checks.py`
- `tests/device-control/suites/smoke.sh`
- `tests/CMakeLists.txt`
- `fic-dick/README.md`
- `fic-gui/README.md`
- `fic-cli/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Выполненные проверки

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11`: успешно.
- `cmake --build build-check -j2`: успешно, собраны все цели.
- `ctest --test-dir build-check --output-on-failure`: 16 тестов, ошибок нет;
  `admin_socket_tests` и root-зависимый `command_hash_batch_tests` штатно
  пропущены.
- Новый `device_tree_revision_tests` проверяет неизменность ревизии при чтении
  и повторной инициализации, её рост при изменении устройств, атрибутов и
  событий, а также сохранение между открытиями БД.
- `bash -n tests/device-control/suites/smoke.sh`: успешно.
- `PRAGMA integrity_check` для обновлённой seed-базы: `ok`; присутствуют одна
  строка состояния и девять триггеров ревизии.
- `git diff --check`: успешно.

## Что осталось

- Ручной запуск GUI и `fic-cli device revision` с реальным
  `fic-dick --daemon` не выполнялись, поскольку production device runtime
  использует системную БД и сокет.
- VM smoke-suite с реальными udev-событиями не запускался; его read-only
  проверка новой команды добавлена.

## Риски и решения

- Проверка ревизии остаётся синхронным IPC-вызовом в GUI-потоке, но больше не
  запускает каскад `device_children`/`device_attributes` при неизменных данных.
- При реальном изменении данных существующее полное синхронное перестроение
  дерева сохраняется. Если оно само вызывает заметную паузу, следующим этапом
  нужны пакетный snapshot API и загрузка вне GUI-потока.
- Ревизия учитывает события, чтобы периодическое обновление выбранного
  устройства не оставляло вкладку событий устаревшей.
