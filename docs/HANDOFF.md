# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `f4a3adcff0dbb971068530b906a7f84a5a43f519`.

## Current task

- Явная область контролируемых DE, единый session-aware policy framework и
  targeted reconciliation по недоверенному `session_ready` hint.

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

- Добавлены typed controlled scope и fixed policy отсутствия неконтролируемых DE.
- `PolicyRegistry` индексирует session-aware/inventory-compliance capabilities.
- `screenlock_timeout` и KDE media controls переведены на общий lifecycle;
  session handlers используют read-before-write/readback verify.
- Добавлены event ingress, logind/peer validation, targeted worker и agent retry.
- Обновлены config, localization, architecture/session-agent docs и tests.

## Changed areas

- `fic-common/fic-policy`, `fic-common/fic-ipc`, `fic/src/session`,
  `fic/src/modules/oss/desktop_environment`, daemon/agent startup, tests/docs.

## Validation

- Fresh `/tmp` configure и full build: passed с
  временными development headers/pkg-config metadata и реальной runtime
  `/usr/lib/x86_64-linux-gnu/libsystemd.so.0`.
- Все 17 релевантных DE/session/IPC tests: passed.
- CTest без уже сломанного в базовом HEAD `module_ui_static_checks`: 65 passed,
  1 environment-dependent test skipped, 0 failed.
- `git diff --check`: passed.

## Remaining

- `module_ui_static_checks` требует старую строку `saveChanges(..., error)`, хотя
  базовый HEAD уже использует `ApplyResult::error`; это вне scope текущей задачи.
- Повторить native configure/build без временных libsystemd headers после
  установки `libsystemd-dev`.
- Реальный systemd/logind multi-session integration не выполнялся.
