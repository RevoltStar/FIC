# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-09.
- Ветка: `main`.
- Базовый commit: `1102d9e`.
- Текущая задача: исправить смешение SYSCTL key semantics после commit
  `1102d9e`, сохранив architecture-модель `SystemdSysctl` + FIC-owned managed
  file.
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
- SYSCTL foreign `sysctl.d/*.conf` symlink теперь обрабатываются по семантике
  systemd-sysctl: `/dev/null` остается mask, symlink на обычный безопасный файл
  читается, symlink на dangling/non-regular/unsafe target отвергается.
- Managed SYSCTL file FIC остается strict non-symlink: `loadManagedDocument()`,
  `writeManaged()` и удаление managed-файла не следуют symlink.
- `SysctlKey.h` разделяет три операции преобразования:
  `systemdConfigKeyToCanonicalPath()` для внешних `sysctl.d` строк,
  `internalKeyToCanonicalPath()` для FIC API/runtime и
  `configKeyFromCanonicalPath()` для генерации managed-файла.
- Внутренний canonical SYSCTL representation — относительный `/proc/sys` path:
  `kernel/pid_max`, `net/ipv4/ip_forward`,
  `net/ipv4/conf/enp3s0.200/forwarding`.
- Parser внешних `sysctl.d` keys больше не использует network-specific
  эвристику. Fully dotted `net.ipv4.conf.enp3s0.200.forwarding` трактуется по
  systemd semantics как `net/ipv4/conf/enp3s0/200/forwarding`, а dotted
  interface должен задаваться однозначно:
  `net/ipv4/conf/enp3s0.200/forwarding` или
  `net.ipv4.conf.enp3s0/200.forwarding`.
- `configKeyFromCanonicalPath()` сохраняет привычную dotted форму для простых
  keys, но для canonical paths с literal dot внутри компонента генерирует
  slash-first syntax, который round-trip'ится через systemd parser без потери
  literal dot.
- Если boot-effective SYSCTL value уже соответствует политике, но FIC managed
  file содержит устаревшее противоречащее назначение, оно удаляется атомарно,
  затем effective value перечитывается; при ошибке выполняется rollback.
- Диагностика source location для symlinked foreign sysctl-файлов показывает
  `link -> resolved-target:line`.

## Измененные файлы

- `fic/src/modules/sysctl/SysctlConfiguration.cpp`;
- `fic/src/modules/sysctl/SysctlKey.h`;
- `fic/src/modules/sysctl/SysctlRuntime.cpp`;
- `tests/sysctl/SysctlConfigurationTests.cpp`;
- `docs/HANDOFF.md`.

## Выполненные проверки

- `cmake --build build-check --target sysctl_configuration_tests -j2` —
  успешно.
- `./build-check/tests/sysctl_configuration_tests` — успешно.
- `ctest --test-dir build-check -R sysctl_configuration_tests --output-on-failure`
  — успешно.
- `cmake --build build-check --target fic -j2` — успешно.
- `cmake --build build-check --target platform_profile_tests -j2` — успешно.
- `./build-check/tests/platform_profile_tests` — успешно.
- `python3 tests/platform/static_checks.py .` — успешно.
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
- `cmake -S . -B /tmp/fic-build-altp11 -DFIC_TARGET_PLATFORM=alt-p11`
  + `cmake --build /tmp/fic-build-altp11 --target fic-platform -j2` —
  успешно.
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
