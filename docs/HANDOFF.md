# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `f4a3adcff0dbb971068530b906a7f84a5a43f519`.

## Current task

- Устранение connect-before-send race в `SessionEventServer` и явная фиксация
  scope semantics ordinary DE-dependent policies.

## Accepted architecture / invariants

- `controlled_desktop_environments=[]` означает `UNCONFIGURED`; scope не
  выводится из platform profile, packages или desktop descriptors.
- Обычные DE policies различают `NotApplicable` и `Unsupported`; compliance
  policy проверяет полный inventory и fail-closed для неизвестного DE.
- Все реализованные screen-lock/KDE media backends остаются `SessionOnly`.
  `MandatoryGlobal` требует раздельных value/protection/verify фаз.
- `session_ready` идёт через отдельный `/run/fic/fic-session-events.sock`, не
  содержит PID/desktop/policy data и только планирует bounded/coalesced work.
- `fic.service`: `Type=notify`, `NotifyAccess=main`, `TimeoutStartSec=600s`;
  `READY=1` следует после listen admin и session-event sockets.

## Completed

- Accepted nonblocking session-event connection теперь bounded ожидает payload;
  `EINTR`/`EAGAIN` повторяются, timeout/error/hangup/close обрабатываются безопасно.
- Добавлен connect-before-send regression, silent-client timeout и recovery
  следующим запросом.
- Ordinary policies явно игнорируют uncontrolled/unknown sessions; dedicated
  compliance policy остаётся fail-closed. Обновлены ru/en descriptions и docs.

## Changed areas

- `fic/src/session/SessionEventServer*`, DE semantic/event tests, ru/en
  localization и архитектурная/session-agent документация.

## Validation

- Full incremental build: passed в `/tmp/fic-de-build` с временными development
  headers/pkg-config metadata и реальной runtime `libsystemd.so.0`.
- 6 релевантных DE/session tests: passed.
- `session_event_server_tests` десять последовательных прогонов: passed.
- CTest без уже сломанного в базовом HEAD `module_ui_static_checks`: 65 passed,
  1 environment-dependent test skipped, 0 failed.
- `git diff --check`: passed.

## Remaining

- `module_ui_static_checks` требует старую строку `saveChanges(..., error)`, хотя
  базовый HEAD уже использует `ApplyResult::error`; это вне scope текущей задачи.
- Повторить native configure/build без временных libsystemd headers после
  установки `libsystemd-dev`.
- Реальный systemd/logind multi-session integration не выполнялся.
