# Device Control new/all: реализация и проверки

Дата: 2026-10-10. Ветка main. Task base:
`76273c79781fd783c777b0577be316221d8c4270`.
Итоговый commit определяется `git log -1` для коммита, содержащего этот отчёт.

## Изменённые production области

* `fic/src/modules/dc`: combobox all/new (default all), независимый ENABLE/DISABLE;
  `DC::apply()` выполняет полный sync трёх категорий. Detector severity сохраняет
  прежнюю validation-only семантику.
* `fic/src/main.cpp`: sync после успешной administrative mutation и reload,
  explicit apply, startup/periodic, включая все DISABLE. Persistent mutation
  не объявляется откатившейся при последующей sync failure.
* `fic-common/fic-device-db`: schema 2, modes/epochs, независимые долговечные
  known identity/attribute snapshots, SQLite BEGIN IMMEDIATE и synchronous FULL.
  Boolean schema 1 явно отклоняется без миграции.
* `fic-dick`: full-state root IPC, shared category matching, runtime/snapshot
  priority, compiler known exceptions, reload и проверяемый current-device DENY.
* DC journal/undo backend полностью удалён; остальные rollback контракты сохранены.
* Config/localization, CMake/CI regressions, existing DC static/VM test contracts,
  `fic-dick/README.md` и `docs/rollback.md` актуализированы.

## Приоритет

| Слой | Поведение |
|---|---|
| ENABLE/all | Абсолютный категорийный DENY, включая explicit ALLOW/IGNORE/PERMANENT и ignore_hierarchy |
| Explicit identity, затем placement | Существующий приоритет явных правил; может перекрыть new |
| ENABLE/new | DENY identity, не доказанной известной на начало эпохи |
| Hierarchy | Ближайший explicit children_control |
| Default | ALLOW |

DISABLE исключает категорию из расчёта; device rules не удаляются.
Shared predicates определяют одинаковую категорийную область runtime,
GUI snapshot и generated udev rules. USB storage не превращается в глобальный
запрет USB peripherals. Для overlapping categories source выбирается
детерминированно, all предшествует new.

## Переходы и identity

| Переход | Epoch/snapshot |
|---|---|
| disabled → new | Новый атомарный snapshot, epoch + 1 |
| all → new | Новый атомарный snapshot, epoch + 1 |
| new → new | Сохранение |
| new → all | Сохранение epoch, абсолютный DENY |
| all → all | Без изменения epoch/revision |
| любой → disabled | Удаление категорийного эффекта, без physical undo |

Snapshot хранит исторические `(device_hash, subsystem)` и identity attributes
отдельно от удаляемых occurrences. Для physical known matching используются
узкие стабильные USB vendor/product/serial и block WWN либо vendor/model/serial.
USB interface связывается с physical USB parent; новая partition того же
WWN не становится новым physical device. DEVPATH, event timestamp и filesystem
UUID не доказывают известность. Missing/unsafe identity не даёт исключение,
включая glob/format/control characters. Неполный последний occurrence не стирает
более раннюю доказанную identity.

Restart, crash/recovery, periodic, regeneration и reconnect сохраняют эпоху.
Identity впервые после snapshot остаётся новой до реального перехода в новую
эпоху. SQL write failure откатывает capture вместе со сменой режима.

Desired revision сохраняется до compilation/publication/activation. Active
revision подтверждается после reload и проверяемого DENY подключённых устройств;
неподтверждённый enforcement инвалидирует active revision. Identical desired
modes не меняют epoch/desired revision; повторный reconcile может ремонтировать
active artifact и pending activation.

## Rollback / disable

Все три известные категории `NotEnrolled`; неизвестная DC policy — `Unsupported`.
Удалены `MutationBackend::DeviceControl`, `UndoDisableDeviceFeature`, serializer,
executor, backend callback и Prepared/commit provenance для DC. Реальные apply /
disable не создают DC records; `rollbackPolicyBeforeDisable` не выполняет DC undo.

Disable: persistent DISABLE → successful registry reload → полный desired-state
sync → SQLite → compile → publish/reload. Ошибка остаётся ошибкой с сохранённым
persistent intent; startup/periodic повторяет sync. При failed persistence или
failed registry reload sync не запускается.

Для current-device DENY используется актуальный udev inventory, существующие
collectors/identity и ограниченный sysfs backend. Глобальный trigger отсутствует.
Отключение, all → new и удаление FIC не отменяют `authorized=0`, SCSI `delete=1`,
PCI `remove=1`: может потребоваться reconnect/rescan.

## Docker матрица

Все строки ниже: production fic/fic-dick/fic-cli build PASS, targeted CTest 10/10,
реальные CLI/IPC и SQLite PASS, DB/compile/publish/activation failures + recovery
PASS, periodic drift в обе стороны PASS, crash/restart epoch PASS,
отсутствие DC rollback PASS, native udevadm test PASS.

| Дистрибутив | Проверенный image/tag | CMake platform | Результат |
|---|---|---|---|
| ALT p11 | fic-dc-gate:altp11 | alt-p11 | PASS |
| Debian 12 | fic-dc-gate:debian12 | debian-12 | PASS |
| Debian 13 | fic-dc-gate:debian13 | debian-13 | PASS |
| Ubuntu 24.04 | fic-dc-gate:ubuntu2404 | ubuntu-24.04 | PASS |
| Ubuntu 26.04 | fic-dc-gate:ubuntu2604 | ubuntu-26.04 | PASS |

Image IDs, по порядку таблицы:

```text
sha256:b489bf0dd79ab1010ea1af6c7c4772f447be3f85d573192e48c6faadb4737fa3
sha256:5e971029345eed70adc867e48038be4298c9785d97fe8b225f7c14cd6e205593
sha256:7519dbd13b672a268995c12fbe658dba4795ec38d01876ae7352721730ce4f79
sha256:aa07ed5b6d8c1631f1c1dc1f0ea945ec70f81ae2acb5d2d0382a3587907a6850
sha256:bce80825a5a83c69c506d1eb712d610b4380097aa01ebe2bb6b3d20262d3ab6f
```

Использованы существующие packaging builders; `Dockerfile.gate` добавляет только
native udev/PAM development dependencies и ALT ctest/Python sqlite3. Test IPC
framing повторно использует helper из existing Device Control VM harness.

Команда каждой строки (TAG/PLATFORM/BUILD соответствуют таблице):

```bash
docker run --rm -e PLATFORM="$PLATFORM" \
  -v /home/admsys/FIC:/src:ro -v "$BUILD":/build \
  "fic-dc-gate:$TAG" bash /src/tests/integration/device-control/container_gate.sh
```

Build/evidence directories:

* Debian12: `build-prelogin-validation/final`;
* ALT: `build-prelogin-validation/cross/altp11`;
* остальные: `build-prelogin-validation/dc-matrix/{debian13,ubuntu2404,ubuntu2604}`.

Каждый содержит `dc-build.log`, `dc-tests.log`, `dc-ipc.log`,
`dc-native-udev.log`, daemon logs. Docker privileged/cap-add и writable host
`/sys` mounts не использовались.

## Уровни доказательства и ограничения

* SQLite: настоящая БД, транзакции, конкурирующий writer/capture, durable restart;
  injected write abort проверяет rollback всей транзакции.
* Реальные daemon/CLI/IPC: source defaults плюс platform-generated defaults,
  настоящая configuration persistence, strict IPC validation, desired/active
  revisions и genuine compile/publish failure. Activation fault и inventory
  используют намеренные test fixtures; это не доказательство live udevd reload.
* Native udevadm test: настоящий distro parser/matcher на read-only virtual
  block sysfs node с controlled properties; проверены known/new, explicit ALLOW,
  all поверх ALLOW/IGNORE/PERMANENT/direct identity. RUN только планируется;
  physical enforcement не выполняется. USB parent rules присутствуют и читаются
  parser; matching physical USB parent отдельно проверяется unit fixtures.
* Sysfs backend: реальные записи только в fixture files, existing enforcer
  regression suite. Аппаратные USB/printer/optical E2E и реальный udevd/systemd
  reboot — SKIP: нет выделенного аппаратного/VM окружения, host mutation запрещена.
* Descriptors/serial/WWN — сообщаемые identifiers, без криптографического доказательства
  происхождения. Подделка identifiers аппаратурой остаётся границей модели;
  [kernel USB authorization documentation](https://docs.kernel.org/usb/authorization.html)
  прямо описывает эту границу.

Полная Debian12 project build PASS. Завершающий full CTest: 171/171 PASS
(`mutation_journal_tests` исключён из root run и отдельно PASS под UID65534).
Первый full run имел flaky `process_cancellation_tests` cleanup assertion;
изолированный rerun и полный завершающий rerun PASS. Код ProcessExecutor не менялся.
`git diff --check` PASS.
