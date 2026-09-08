# FIC: передача контекста

## Current base

- Ветка `main`, commit `71dff9f` (audit value sanitization).
- До текущей задачи рабочее дерево было чистым.

## Current task

- Ограничение совокупного stdout/stderr в обычном и verified ProcessExecutor.

## Accepted architecture / invariants

- `ProcessOptions::maxOutputBytes`: общий capture budget, default 4 MiB.
  Ровно budget разрешён, следующий байт — failure. Zero разрешает пустой вывод.
  stdin не входит в budget. Runtime contract: `docs/architecture-diagrams.md`.
- Оба readers атомарно резервируют общий остаток, сохраняют только помещающуюся
  часть chunk и далее drain/discard. Parent использует существующий 20 ms polling
  и group SIGKILL с fallback на PID. Мониторинг продолжается до окончания I/O;
  waitid WNOWAIT удерживает PID лидера до завершения draining и final waitpid.
- `outputLimitExceeded=true`, `timedOut=false`, `success()==false`, явная bounded
  diagnostic с configured limit. Overflow имеет приоритет, включая final drain;
  exitCode остаётся фактическим статусом лидера (может быть 0).
- Только full nft ruleset и udev export-db имеют override 32 MiB: размер растёт
  со всей конфигурацией хоста. Остальные callers (DMI 2/17, lscpu, loginctl,
  systemctl, sshd, visudo, GRUB/PAM activation, chage/gpasswd, desktop settings,
  метаданные одного пакета dpkg/RPM) сохраняют default 4 MiB.

## Completed / Changed areas

- `fic-common/fic-core/include/fic/core/process/ProcessExecutor.h`,
  `fic-common/fic-core/src/process/ProcessExecutor.cpp`: API, shared limiter,
  group termination и ожидание I/O потомков; fd-bound exec path сохранён.
- Overrides: `fic/src/modules/firewall/FirewallBackend.cpp`,
  `fic-dick/src/daemon/DeviceControlDaemon.cpp`.
- `tests/common/core/process/ProcessOutputLimitTests.cpp`, `tests/CMakeLists.txt`:
  одинаковые suites для plain/verified, stdout/stderr, общий конкурентный budget,
  ровно budget/+1, 0/1, finite default+1, paced infinite output, descendants
  holding pipes / generating after leader exit, stdin budget exclusion и blocked
  stdin writer, обычный timeout. SIGKILL потомка проверен через subreaper/waitpid.
- Обновлено непосредственно относящееся архитектурное описание.

## Validation

- Configure `/tmp/fic-dev-build`, ubuntu-24.04,
  `PKG_CONFIG_PATH=/tmp/fic-dev-tree/pkgconfig`: success.
- Targeted build `fic-core process_output_limit_tests verified_process_executor_tests`:
  success; targeted CTest (оба tests + platform/path-layout static): 4/4 passed.
- `python3 tests/fic/platform/static_checks.py .`,
  `python3 tests/common/static_checks.py .`: passed.
- Negative control в `/tmp`: прежний executor падает на строгом sum <= budget
  assertion при конечном stdout default+1; production sources не подменялись.
- `cmake --build /tmp/fic-dev-build -j2`: success.
- `ctest --test-dir /tmp/fic-dev-build --output-on-failure` вне sandbox:
  75 passed, 1 skipped (root-only command_hash_batch_tests), 0 failed.
- Read-only host measurements: udev export 324905 bytes, lscpu 3386 bytes,
  RPM filenames/digests для владельца /usr/bin/udevadm 9351 bytes; stderr пуст.
  loginctl/dmidecode/nft вернули ошибки, успешный вывод не измерен.
- Логи: `/tmp/fic-output-{configure,target-build,full-build,full-ctest}.log`.
- Финальный diff review выполнен; `git diff --check`: clean.

## Remaining

- Незавершённых изменений по задаче нет. Podman, реальные большие nft/device
  topologies и root-only test не запускались. Измерения одной машины не являются
  верхней границей реальных ответов; oversized ответы отклоняются явно.
- Сборка использует существующий stub libsystemd в `/tmp/fic-dev-tree/*`.
- Коммит не создавать без отдельного запроса пользователя.
