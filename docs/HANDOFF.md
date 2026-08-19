# FIC: передача контекста

## Current base

- Дата: 2026-08-19.
- Ветка: `main`.
- Базовый commit задачи: `9711316` (`Устраняем race-condition между display-manager и fic. Теперь fic для определения DE не ожидает, что она прямо сейчас запущена`).

## Current task

- Исправлен lifecycle Device Control для последовательности `DENY -> successful
  enforcement -> remove events`.

## Accepted architecture / invariants

- `boot_id` означает присутствие occurrence в текущей boot-session и не зависит
  от результата policy enforcement.
- Успешный `DENY` сохраняет current `boot_id`; переход в disconnected выполняет
  только real remove или reconciliation отсутствующего в sysfs устройства.
- Remove выбирает occurrence строго по `devpath + subsystem + current boot_id` и
  атомарно сохраняет affected IDs, очищает current subtree и пишет disconnect event.
- Duplicate/already-removed remove является успешным no-op без создания nodes и
  без выбора historical occurrence.

## Completed

- Добавлен небольшой транзакционный `DeviceLifecycle` и удалён старый
  parent-dependent `UDEVInfoCollector::safe_remove_device()`.
- Real remove стал current-boot exact и идемпотентным; permanent check получает
  сохранённые до mutation affected IDs.
- Synthetic inventory events reconciliation больше не интерпретируются как
  выполненный udev enforcement; startup reconciliation сохранён и сообщает о
  lifecycle/DB failures вызывающей очереди.
- Добавлены regression tests для DENY presence, обоих порядков parent/child
  remove, duplicate remove, multi-boot, lost remove, reboot и virtual parents.

## Changed areas

- `fic-dick/src/core/DeviceControlDaemon.cpp`, `DeviceLifecycle.*`;
- `fic-dick/src/modules/UDEVInfoCollector.*`;
- `tests/device-control`, `tests/CMakeLists.txt`.

## Validation

- `cmake -S . -B /tmp/fic-device-lifecycle-build
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` - успешно.
- `cmake --build /tmp/fic-device-lifecycle-build -j2` - успешно.
- `ctest --test-dir /tmp/fic-device-lifecycle-build --output-on-failure` -
  40/40 без ошибок; 3 host-dependent теста штатно пропущены.
- `python3 tests/device-control/static_checks.py .` - успешно.
- `git diff --check` - успешно.
- Реальный udev/device enforcement на рабочем хосте не запускался.

## Remaining

- Диагностический USB HID сценарий не воспроизводился на отдельном staging host;
  поведение подтверждено unit/contract/static tests.
