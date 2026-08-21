# FIC: передача контекста

## Current base

- Дата: 2026-08-21.
- Ветка: `main`.
- Базовый commit задачи: `ac949e1` (`Обновляем профиль для alt11`).

## Current task

- Устранение гонки между обнаружением графической сессии и запуском
  `fic-session-agent` через XDG Autostart.

## Accepted architecture / invariants

- Daemon ожидает готовность session-agent не более 10 секунд с интервалом
  200 мс.
- Повторяются только безопасные состояния запуска: отсутствующий socket
  (`ENOENT`) и временный отказ подключения (`ECONNREFUSED`).
- Неверный тип/владелец socket, неожиданные ошибки подключения, неверный peer
  UID и ошибки протокола завершают запрос немедленно.
- Проверки типа и владельца socket выполняются заново перед каждой попыткой
  подключения.

## Completed

- В `SessionAgentClient` добавлено ограниченное ожидание готовности agent
  socket без изменения публичного API.
- Добавлены тесты отложенного создания socket, временного `ECONNREFUSED`,
  завершения по timeout и немедленного отказа для небезопасного пути.
- Runtime-контракт session agent актуализирован в документации.

## Changed areas

- `fic/src/session/SessionAgentClient.cpp` и test-only internal interface;
- `tests/session/SessionAgentClientTests.cpp`, `tests/CMakeLists.txt`;
- `docs/session-agent.md`.

## Validation

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build build-check --target session_agent_client_tests fic -j2` —
  успешно.
- `ctest --test-dir build-check -R '^session_agent_client_tests$' --output-on-failure`
  вне sandbox — успешно, 1/1.
- Полный `ctest --test-dir build-check --output-on-failure`: 36 тестов
  успешно, 4 пропущены из-за sandbox, 1 известный несвязанный сбой
  `ipc_protocol_validation_tests` из-за противоречивых проверок одного
  status request.

## Remaining

- Изменения не развёртывались на ALT-машине `10.88.0.250`; после сборки
  пакета нужна staging-проверка применения session-зависимой политики сразу
  после входа пользователя.
- Несвязанный сбой `ipc_protocol_validation_tests` в scope задачи не
  исправлялся.
