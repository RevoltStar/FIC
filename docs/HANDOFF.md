# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-09.
- Ветка: `main`.
- Базовый commit: `d693cd7`.
- Текущая задача: переработать SYSCTL persistent-конфигурацию под
  platform-selected loader semantics и FIC-owned managed file.
- Реализация завершена, изменения рабочей копии не зафиксированы commit.

## Сделано

- `fic-dick --daemon` выполняет initial/full reconciliation текущего
  udev/sysfs inventory самостоятельно через `udevadm info --export-db`.
- Boot inventory больше не строится через массовый `udevadm trigger --action=add`.
- Общая обработка одного устройства сведена к `process_device_event()`, которую
  используют и compatibility/admin `udev_event`, и initial reconciliation, и
  runtime event queue.
- Добавлен отдельный runtime endpoint `/run/fic/fic-device-events.sock` для
  udev ingress:
  - `AF_UNIX/SOCK_DGRAM`;
  - `SO_PASSCRED`;
  - root sender credentials check через `SCM_CREDENTIALS`;
  - socket mode `0600`;
  - bounded payload `64 KiB`.
- `fic-dick udev` больше не использует административный request/response IPC.
  Он отправляет один bounded datagram и быстро завершается.
- Добавлена bounded in-memory queue для device events (`MAX_DEVICE_EVENT_QUEUE`),
  coalescing redundant `change` по `SUBSYSTEM + DEVPATH`, overflow dirty flag и
  forced reconciliation.
- Если helper не может доставить event datagram, он пишет runtime marker
  `/run/fic/fic-device-reconcile.required`; daemon забирает marker и выполняет
  reconciliation.
- Если helper не может доставить event datagram или payload слишком велик, а
  reconciliation marker создать не удалось, `fic-dick udev` возвращает `1`.
  Успешный exit code `0` означает, что event реально доставлен или
  reconciliation реально запланирована.
- При daemon restart reconciliation выполняется автоматически, поэтому события,
  потерянные во время downtime, не оставляют БД постоянно рассинхронизированной.
- `fic-udevadm-trigger` теперь только ждёт готовности device daemon и запускает
  `check-permanent`; `udevadm trigger`/`udevadm settle` удалены.
- Документация разделяет initial reconciliation и runtime event ingestion и
  фиксирует, что udev stream является notification mechanism, а не единственным
  source of truth.
- Добавлен runtime shell suite `ingestion` и расширены static checks.
- `fic` daemon выполняет отдельный daemon enforcement pass:
  `init_policyMap()` + `applyAllPolicies()` + `isPolicyApplySuccessful()` для
  причин `startup` и `periodic`.
- После создания административного socket, но до сообщения `fic daemon started`,
  выполняется стартовое применение всех включенных политик.
- Ошибка стартового применения является fail-closed: daemon закрывает и удаляет
  socket, пишет ошибку и завершается с кодом `1`.
- Периодический контроль по `--interval` использует тот же daemon enforcement
  pass вместо CLI-ориентированного `apply(policyMap, "all", "")`.
- Результаты daemon enforcement pass пишутся в stdout/stderr и audit log с
  причиной (`startup` или `periodic`) и агрегированными счетчиками.
- На машине `172.17.1.150` подтверждено: запись
  `net.ipv4.tcp_synack_retries` в `daemon_1392.txt` присутствовала один раз, но
  GUI показывал ее многократно. Причина была не в записи daemon log, а в
  чтении логов: `boot_id` и `log_records` сами писали audit-записи в тот же
  каталог `/opt/fic/log/<boot_id>`, который затем читался offset-пагинацией.
  Новые audit-записи появлялись перед daemon-файлом и сдвигали cursor, поэтому
  GUI повторно получал уже прочитанные строки.
- `boot_id` и `log_records` исключены из IPC audit path, чтобы polling/read path
  LogViewer был read-only относительно читаемого журнала.
- Добавлена static check, фиксирующая этот контракт.
- `PlatformProfile` расширен `SysctlPlatformConfig`: профиль явно задает loader
  (`SystemdSysctl`) и FIC-owned managed path `/etc/sysctl.d/zzzz-fic.conf`.
- Все поддерживаемые профили (`debian-12`, `debian-13`, `ubuntu-24.04`,
  `ubuntu-26.04`, `alt-p11`) настроены на `SystemdSysctl`.
- `SysctlConfiguration` больше не пишет policy values в `/etc/sysctl.conf`.
  Для systemd-профилей boot-effective значение считается по `sysctl.d/*.conf`,
  с приоритетом одинаковых имен по каталогам, глобальной лексикографической
  сортировкой, glob/exclusion semantics и source location.
- `/etc/sysctl.conf` больше не считается boot-effective source для
  `SystemdSysctl`; он не исправляется и не используется как FIC-owned файл.
- Remediation пишет только `/etc/sysctl.d/zzzz-fic.conf`; если корректное
  значение уже задано чужим active `sysctl.d` файлом, FIC не создает дубль.
- Если после записи managed-файла другой later source перекрывает значение,
  операция завершается conflict/failure с диагностикой `expected/actual/path:line`
  и откатом managed-файла. Чужие sysctl-файлы не изменяются.
- `Sysctl::apply()` получает SYSCTL platform config из `init_policyMap()` и
  сохраняет отдельную runtime remediation через `SysctlRuntime`.

## Измененные файлы

- `fic-dick/src/core/DeviceControlDaemon.cpp`;
- `fic/src/main.cpp`;
- `fic/src/scripts/service/fic-udevadm-trigger.in`;
- `fic/src/core/main_function.cpp`;
- `fic/src/modules/sysctl/Sysctl.cpp`;
- `fic/src/modules/sysctl/Sysctl.h`;
- `fic/src/modules/sysctl/SysctlConfiguration.cpp`;
- `fic/src/modules/sysctl/SysctlConfiguration.h`;
- `fic/src/platform/PlatformCompatibility.cpp`;
- `fic/src/platform/PlatformProfile.h`;
- `fic/src/platform/profiles/AltP11Profile.cpp`;
- `fic/src/platform/profiles/Debian12Profile.cpp`;
- `fic/src/platform/profiles/Debian13Profile.cpp`;
- `fic/src/platform/profiles/Ubuntu2404Profile.cpp`;
- `fic/src/platform/profiles/Ubuntu2604Profile.cpp`;
- `fic-dick/README.md`;
- `docs/architecture-diagrams.md`;
- `packaging/deb/README.md`;
- `packaging/rpm/README.md`;
- `tests/platform/PlatformProfileTests.cpp`;
- `tests/platform/static_checks.py`;
- `tests/device-control/static_checks.py`;
- `tests/device-control/test.sh`;
- `tests/device-control/suites/ingestion.sh`;
- `tests/sysctl/SysctlConfigurationTests.cpp`;
- `tests/sysctl/RemoteSysctlIntegration.sh`;
- `docs/HANDOFF.md`.

## Выполненные проверки

- `cmake --build build-check --target fic-dick fic -j2` — успешно.
- `cmake --build build-check --target fic -j2` — успешно.
- `cmake --build build-check --target fic-gui -j2` — успешно.
- `cmake --build build-check --target sysctl_configuration_tests -j2` — успешно.
- `./build-check/tests/sysctl_configuration_tests` — успешно.
- `cmake --build build-check --target platform_profile_tests -j2` — успешно.
- `./build-check/tests/platform_profile_tests` — успешно.
- `bash -n tests/sysctl/RemoteSysctlIntegration.sh` — успешно.
- `cmake -S . -B /tmp/fic-build-debian12 -DFIC_TARGET_PLATFORM=debian-12`
  + `cmake --build /tmp/fic-build-debian12 --target fic-platform -j2` —
  успешно.
- `cmake -S . -B /tmp/fic-build-debian13 -DFIC_TARGET_PLATFORM=debian-13`
  + `cmake --build /tmp/fic-build-debian13 --target fic-platform -j2` —
  успешно.
- `cmake -S . -B /tmp/fic-build-ubuntu2404 -DFIC_TARGET_PLATFORM=ubuntu-24.04`
  + `cmake --build /tmp/fic-build-ubuntu2404 --target fic-platform -j2` —
  успешно.
- `cmake -S . -B /tmp/fic-build-ubuntu2604 -DFIC_TARGET_PLATFORM=ubuntu-26.04`
  + `cmake --build /tmp/fic-build-ubuntu2604 --target fic-platform -j2` —
  успешно.
- `python3 tests/device-control/static_checks.py .` — успешно.
- `python3 tests/platform/static_checks.py .` — успешно.
- `bash -n tests/device-control/test.sh tests/device-control/suites/ingestion.sh`
  — успешно.
- `git diff --check` — успешно.

## Что осталось

- Runtime suite `tests/device-control/test.sh --yes-i-know-this-mutates-vm
  --type ingestion` не запускался локально, потому что он требует управляемый VM
  стенд и меняет состояние тестовой машины.
- Полный device-control VM test matrix не запускался.

## Риски и решения

- Initial reconciliation использует `udevadm info --export-db`, а не libudev API.
  Это сознательный выбор для минимального изменения: проект уже полагается на
  udev environment и `udevadm`, а collectors остаются единым местом
  идентификации устройств.
- Во время самой initial reconciliation event socket уже создан, но daemon
  обрабатывает очередь после reconciliation. Если producer не может доставить
  datagram, он ставит reconciliation marker. Если datagram доставлен, он будет
  обработан после initial pass.
- Compatibility/admin IPC-команда `udev_event` оставлена root-only для
  существующих тестов и отладочных сценариев, но production udev rule больше не
  использует этот путь.
- В producer path запрещён silent success: при недоставленном событии и
  невозможности создать marker helper должен завершиться ошибкой, чтобы udev не
  считал обработку успешной без гарантии дальнейшего reconciliation.
