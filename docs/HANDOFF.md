# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `c1197c58ea2dd5a8d0a4a5e8fae03c64ae4c95f8`.

## Current task

- Однозначный UID-session fallback для systemd-managed GNOME, когда
  `fic-session-agent` не принадлежит конкретной logind session.

## Accepted architecture / invariants

- `fic-session-agent` остаётся per-graphical-session context provider; daemon
  остаётся authoritative источником sessions для применения policies.
- Identity resolution: validated `XDG_SESSION_ID`, затем session собственного
  PID, затем — только после точного `-ENODATA` — sessions текущего UID.
- Найденная process session authoritative: SSH/TTY/remote/non-user/foreign UID
  приводит к fail-closed без UID fallback.
- Hard error `sd_pid_get_session()` приводит к fail-closed без UID fallback.
- UID fallback использует `sd_uid_get_sessions(uid, 0, ...)`, общий predicate
  UID + `Class=user` + `Remote=no` + `Type=x11|wayland|mir` и принимает только
  ровно одного graphical candidate.
- `Active`, seat, display, порядок и primary-session эвристики не используются;
  несколько graphical sessions остаются неоднозначными и fail-closed.
- Socket/runtime directory/root-peer и daemon-side UID/session mismatch checks
  не изменены.

## Completed

- Provider API различает `Found`, `NotAssociated` и `Error` для process session.
- Production provider сопоставляет только `-ENODATA` с `NotAssociated` и
  перечисляет online sessions без active-only фильтра.
- Resolver фильтрует enumeration через ту же validation logic и выдаёт точные
  diagnostics для zero/multiple candidates и hard errors.
- Добавлены regression tests для ALT `{Wayland, manager, SSH}`, process-bound
  SSH/TTY/remote/foreign UID, hard error, ambiguity, Active state и unsafe IDs.
- Обновлены static architecture checks и `docs/session-agent.md`.

## Changed areas

- `fic-session-agent/src/SessionIdentityResolver.*`;
- `fic-session-agent/src/SystemdLogindSessionProvider.*`;
- `tests/fic-session-agent/`;
- `docs/session-agent.md`.

## Validation

- `fic-session-agent` и `session_identity_resolver_tests` — успешно собраны в
  ALT p11 build `/tmp/fic-session-agent-build`.
- Targeted resolver/static tests — 2/2 успешно.
- Production libsystemd path без `XDG_SESSION_ID` и process association дошёл
  до `XDG_RUNTIME_DIR` validation, подтвердив успешный unique-candidate fallback.
- `session_agent_client_tests` успешно выполнен вне sandbox, включая daemon-side
  session mismatch regression.
- Полная сборка проекта — успешно.
- Полный CTest: 44 passed, 4 sandbox-skipped, 1 существующий unrelated failure —
  `ipc_protocol_validation_tests` assertion об API v1 request.
- Provider и resolver/tests отдельно собраны с `-Wall -Wextra -Werror`.
- `git diff --check` — успешно.

## Remaining

- Обновлённый binary не устанавливался на `10.88.0.86`; package/runtime test
  реального ALT GNOME autostart после этой доработки ещё не выполнен.
- При двух simultaneous GUI sessions одного UID и отсутствии session-bound
  identity agent намеренно завершается fail-closed; launch mechanism не менялся.
- Debian/Ubuntu container builds не запускались: Docker daemon отсутствует.
- Существующий unrelated `ipc_protocol_validation_tests` failure не исправлялся.
