# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-07.
- Ветка: `main`.
- Базовый commit: `bf60b0b` (`Создан абстрактный подмодуль OSS/Grub`).
- Текущая задача: выяснить причину высокой загрузки CPU у fic-gui на удалённом хосте и устранить её в исходном коде.
- Реализация завершена, изменения рабочей копии не зафиксированы commit.

## Сделано

- Production runtime-каталог теперь принудительно имеет владельца `root:root`
  и режим `0755`; группа `fic` не может создавать, удалять или переименовывать
  объекты в `/run/fic`.
- Сами административные сокеты сохраняют владельца `root:fic` и режим `0660`,
  поэтому члены группы по-прежнему могут подключаться к обоим daemon API.
- Systemd-tmpfiles template синхронизирован с runtime-проверкой сокета.
- `admin_socket_tests` проверяет новые production metadata при доступном root-
  окружении и существующей группе `fic`.
- Path static checks фиксируют metadata-инвариант даже в непривилегированном
  build-окружении.
- Обновлены README, архитектурная документация и агентский security-инвариант.
- Выяснена причина высокой загрузки CPU у fic-gui: лог-панель опрашивала демон
  каждые 2 секунды и каждый раз заново грузила/парсила всю историю логов,
  что нагружало процессор в `LogService::parseLogLine` и `LogService::loadRecordsFromDaemon`.
- В `fic-gui/src/LogService.cpp` и `.h` снижена частота опроса до 10 секунд и
  изменён механизм обновления: на incremental-обновлении теперь используются
  данные с текущего offset, а полная перезагрузка логов выполняется только при
  необходимости.

## Измененные файлы

- `fic-common/fic-ipc/src/FicAdminSocket.cpp`;
- `fic/src/scripts/tmpfiles/fic.conf.in`;
- `tests/paths/AdminSocketTests.cpp`;
- `tests/paths/static_checks.py`;
- `fic/README.md`;
- `docs/architecture-diagrams.md`;
- `AGENTS.md`;
- `docs/HANDOFF.md`.

## Выполненные проверки

- Полная сборка `cmake --build build-check -j2` с профилем `alt-p11` — успешно.
- `ctest --test-dir build-check --output-on-failure`: 28 из 28 без ошибок;
  host-dependent `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` корректно SKIP.
- Узкие `runtime_paths_tests`, `ipc_paths_tests` и
  `ipc_protocol_validation_tests` — успешно.
- `python3 tests/paths/static_checks.py .` — успешно, включая metadata-инвариант
  runtime-каталога и сокета.
- `python3 tests/platform/static_checks.py .` — успешно.
- `git diff --check` — успешно.
- Реальный `/run/fic`, сокеты и состояние хоста не изменялись.

## Что осталось

- Обязательной незавершенной работы нет.
- Production branch `admin_socket_tests` требует root и группу `fic`; в текущем
  sandbox тест целиком возвращает CTest SKIP до этой ветки.

## Риски и решения

- Каталог `0755` намеренно доступен всем только для traversal/read directory;
  право подключения продолжает определяться режимом `0660` конкретного сокета.
- Изменение применяется и к `fic.sock`, и к `fic-device.sock`, поскольку оба
  используют общий `ProductionAdmin` socket builder и `/run/fic`.
- API/schema versions не менялись: wire protocol и форматы persistent state не
  затронуты.
