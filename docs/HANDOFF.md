# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-01.
- Ветка: `main`.
- Базовый commit: `89d21c9`.
- Текущая задача: production hardening административного IPC (`fic` и
  `fic-dick`) против idle/oversized/non-reading клиентов.
- Изменения рабочей копии не зафиксированы commit.

## Сделано

- Старый `SOCK_STREAM + newline + shutdown + EOF` административный протокол
  целиком заменен на Linux `AF_UNIX/SOCK_SEQPACKET`; compatibility-слой не
  добавлялся, так как стабильного API у проекта пока нет.
- Запрос передается одним JSON-пакетом до 64 КиБ. Ответ до 1 МиБ разбивается на
  пакеты до 60 КиБ с 16-байтным network-order заголовком
  `magic/total-size/offset/chunk-size`.
- Общий `fic::ipc::Client` получил неблокирующие connect/send/receive и единый
  deadline 30 секунд. Ошибки сериализации, размера, framing и timeout
  возвращаются в стандартном `{"ok":false,"message":...}`.
- `AdminSocketTransport` обслуживает неблокирующим `poll` до 32 соединений,
  закрывает клиента без первого пакета через 2 секунды и клиента, не читающего
  ответ, через 5 секунд. За один цикл обработчику передается не более одного
  запроса; мутации остаются последовательными, а idle-клиенты не задерживают
  periodic apply.
- `fic` и `fic-dick` переведены на общий transport. `SO_PEERCRED`, audit и
  socket permission model `root:fic 0770/0660` сохранены.
- Добавлена общая проверка JSON: object, обязательный строковый `command`,
  глубина до 16, строка до 16 КиБ, контейнер до 4096 элементов. Для полей API
  проверяются типы и integer range; лишние поля запрещены у мутирующих команд.
- `log_records` переведен на страницы: `offset`, `limit` 1..500,
  `has_more/next_offset`, до 768 КиБ на страницу и 16 КиБ на строку. GUI
  синхронно обновлен и загружает страницы. `boot_id` больше не допускает path
  traversal. `device_events.limit` ограничен диапазоном 1..500.
- Legacy IPC графического session-agent оставлен на отдельном root-to-user
  `SOCK_STREAM`-контракте, но его чтение запроса теперь также ограничено 64 КиБ.
- Python helper device-control integration tests переведен на новый wire
  protocol; обновлены `AGENTS.md`, README и архитектурные диаграммы.

## Основные измененные файлы

- `fic-common/fic-ipc/include/fic/ipc/{FicIpcClient,FicIpcTransport}.h`;
- `fic-common/fic-ipc/src/{FicAdminSocket,FicIpcClient,FicIpcTransport}.cpp` и
  внутренний `FicIpcWire.h`;
- `fic/src/main.cpp`, `fic-dick/src/core/DeviceControlDaemon.cpp`;
- `fic-gui/src/LogService.cpp`, `fic-session-agent/src/main.cpp`;
- `tests/paths/{IpcProtocolValidationTests,IpcTransportTests}.cpp`;
- `tests/device-control/lib/common.sh`, `tests/CMakeLists.txt`;
- `AGENTS.md`, `fic/README.md`, `fic-dick/README.md`,
  `docs/architecture-diagrams.md`.

## Выполненные проверки

- Полная Release-конфигурация `alt-p11` в `/tmp/fic-ipc-build`: успешно.
- `cmake --build /tmp/fic-ipc-build -j2`: успешно, собраны все цели, включая
  `fic`, `fic-dick`, `fic-cli`, `fic-gui` и `fic-session-agent`.
- `ctest --test-dir /tmp/fic-ipc-build --output-on-failure`: 23 теста, ошибок
  нет; sandbox-зависимые `ipc_transport_tests`, `admin_socket_tests` и
  root-зависимый `command_hash_batch_tests` штатно пропущены.
- `/tmp/fic-ipc-build/tests/ipc_transport_tests` вне filesystem sandbox:
  успешно. Проверены multi-frame ответ около 900 КиБ, границы запроса
  64 КиБ/64 КиБ + 1, `MSG_TRUNC`, idle timeout, non-reading клиент и
  отзывчивость параллельного клиента.
- `git diff --check`: успешно.
- Реальные `/run/fic`, `/opt/fic`, службы, политики и device state не
  изменялись.

## Что осталось

- На disposable VM выполнить package install/upgrade и проверить совместную
  перезагрузку daemon/client binaries: старый и новый wire protocol намеренно
  несовместимы.
- В root-capable CI запускать `ipc_transport_tests`, `admin_socket_tests` и
  `command_hash_batch_tests` без sandbox skip.
- Добавить coverage-guided fuzzing JSON/framing boundary; текущие негативные
  тесты детерминированы и не заменяют fuzzer.

## Риски и решения

- Обработчик одной валидной команды исполняется синхронно. Это сохраняет
  сериализацию privileged mutations; idle, oversized и non-reading клиенты его
  больше не блокируют, но зависшая системная операция внутри самой политики
  по-прежнему требует отдельных timeout/cancellation на уровне
  `ProcessExecutor`/политики.
- `log_records` использует числовой offset, а не snapshot cursor. При
  одновременном добавлении/ротации файлов одна многостраничная загрузка может
  кратковременно увидеть дубликат или пропуск; следующий GUI refresh перечитает
  журнал заново.
- Лимит 1 МиБ применяется после выполнения command handler. Известные
  потенциально крупные log/event API ограничены до формирования ответа;
  дальнейшие API с растущими коллекциями должны сразу проектироваться с
  пагинацией.
- Старый и новый IPC нельзя смешивать в работающем комплекте. Это осознанная
  чистая замена до первого стабильного релиза, не migration bug.
