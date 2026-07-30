# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-30.
- Ветка: `main`.
- Базовый commit: `f4b86ec`.
- Текущая задача: перевести категорийные политики контроля устройств DC с
  настраиваемого списка `false`/`true` на фиксированное значение `true`.
- Реализация и локальная проверка завершены, изменения не зафиксированы commit.

## Сделано

- `block_usb_storage`, `block_printers_scanners` и `block_optical_drives`
  используют `FixedPolicyTypeValue("true")`.
- Статус `ENABLE`/`DISABLE` стал единственным переключателем категорийных
  DC-правил; `fic-dick` больше не читает их `.value`.
- Seed `DC.conf` хранит фиксированное значение `true`.
- Поддержка и миграция конфигов прежней модели намеренно не выполняются.
- Device-control сценарии управляют DC-политикой только через статус.
- Статические проверки и документация обновлены под новую модель.

## Измененные файлы

- `fic/src/modules/dc/DC.cpp`
- `fic/src/scripts/config/DC.conf`
- `fic-dick/src/core/DeviceControlDaemon.cpp`
- `tests/device-control/static_checks.py`
- `tests/device-control/lib/common.sh`
- `tests/device-control/suites/*.sh`
- `fic/README.md`
- `fic-dick/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Выполненные проверки

- `python3 tests/device-control/static_checks.py .`: успешно.
- `bash -n tests/device-control/lib/common.sh tests/device-control/suites/*.sh`:
  успешно.
- `cmake --build build-check --target fic fic-dick fic-gui -j2` при
  `FIC_TARGET_PLATFORM=alt-p11`: успешно.
- `ctest --test-dir build-check --output-on-failure`: 14 тестов, ошибок нет;
  `admin_socket_tests` и `command_hash_batch_tests` штатно пропущены.
- `git diff --check`: успешно.

## Что осталось

- Runtime-набор `tests/device-control` в VM не запускался: он выполняет реальные
  udev/device mutations и требует подготовленного тестового окружения.
- Пакеты deb/rpm не собирались.

## Риски и решения

- Существующие конфиги с прежними настраиваемыми DC-значениями не
  преобразуются. Перед использованием новой версии конфигурация должна
  соответствовать новой модели с фиксированным `.value=true`.
- Политики по-прежнему возвращают фиксированное значение `true` через API
  `policy_value`, но GUI отображает их как label и не отправляет
  `set_policy_value`.
