# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `1de6568`.

## Current task

- Исправление опасного fallback с block-device DENY на PCI `remove` в
  `DeviceEnforcer`.

## Accepted architecture / invariants

- Тип subsystem ограничивает допустимый destructive sysfs endpoint.
- `block` использует только ancestor `delete`, чей `subsystem` symlink
  canonical-resolve'ится в `<sysfs>/bus/scsi`; отсутствие такой цели означает
  fail closed без поиска `remove`.
- `pci` использует только `<DEVPATH>/remove`, если сам `DEVPATH` подтверждён
  как `<sysfs>/bus/pci`; поиск по PCI ancestors запрещён.
- USB/usbmisc сохраняет существующий поиск `authorized` и запись `0`.

## Completed

- Sysfs enforcement вынесен во внутренний `DeviceEnforcerSysfs` с production
  default `/sys` и injectable root для тестов.
- Удалена неверная проверка имени каталога `"device"` и общая ветка
  `block || pci`.
- Добавлены runtime-style regression tests с fake sysfs и subsystem symlinks:
  безопасный SCSI `delete`, fail-closed block, настоящий PCI `remove`, запрет
  parent PCI fallback и сохранение USB `authorized=0`.
- Обновлены device-control static invariants и описание enforcement.

## Changed areas

- `fic-dick/src/core/DeviceEnforcer*`;
- `tests/device-control/DeviceEnforcerTests.cpp` и `static_checks.py`;
- `tests/CMakeLists.txt`;
- `fic-dick/README.md`.

## Validation

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build build-check --target device_enforcer_tests fic-dick -j2` —
  успешно.
- Финальный device-control CTest subset: 6/6 успешно
  (`device_control_static_checks`, tree revision/snapshot, policy compiler,
  lifecycle, enforcer).
- `git diff --check` — успешно.

## Remaining

- Реальная запись в host sysfs не запускалась и не нужна как обычная
  validation.
- VM/device-control shell suites с настоящим hotplug не запускались.
