# FIC: передача контекста

## Current base

- Ветка `main`; production KDE system-backend commit поверх `852146b`
  (актуальный SHA см. в `git log -1`).

## Current task

- `OSS/DesktopEnvironment/screenlock_timeout` переведён для KDE из
  `SessionOnly` в `MandatoryGlobal` через production `KdeSystemBackend`.

## Accepted architecture / invariants

- GNOME и KDE — `MandatoryGlobal`; XFCE/FLY — `SessionOnly`; LXQt —
  `Unsupported`. KDE media-controls остаётся `SessionOnly`.
- KDE system state — `/etc/xdg/kscreenlockerrc`, group `[Daemon]`, ровно пять
  active requirements: `Autolock=true`, `Timeout=N`, `Lock=true`,
  `LockGrace=0`, `RequirePassword=true`, каждый key с `[$i]`.
- Backend merge-сохраняет comments, blank lines, unrelated groups/keys и
  inactive stale state. `DISABLE -> no cleanup`; rollback/provenance вне scope.
- Secure filesystem contract: fd-based `openat/O_NOFOLLOW`, trusted owner, no
  group/world write, full ordinary-user ancestor traversal, atomic write и
  `fsync`; foreign `0750` fail closed/no chmod, `0751` допустим, FIC-created
  directories получают `0755`, config обязан быть world-readable regular file.
- Effective proof запускает optional verified `kreadconfig6/5` в clean
  temporary HOME/XDG_CONFIG_HOME с conflicting user file и controlled
  XDG_CONFIG_DIRS; все пять system `[$i]` values должны победить.
- Current-session KDE handler дополнительно читает, пишет и повторно читает
  `Lock=true`, затем сохраняет прежний D-Bus configure call.

## Completed / changed areas

- Добавлены `KdeSystemBackend.{h,cpp}` и `KdeSystemBackendTests.cpp`.
- Обновлены screenlock contributor/mode, KDE session handler, daemon backend
  registration и GNOME/KDE isolation tests.
- Добавлен optional `ExecutableId::Kreadconfig` во все platform profiles с
  secure real-binary и `/usr/bin` candidates; обновлены resolver tests/static.
- Обновлены `session-agent.md` и `architecture-diagrams.md`.

## Validation

- Реальный KConfig experiment: `/bin/kreadconfig6` (real file
  `/usr/lib/kf6/bin/kreadconfig6`) — `[$i]` system values победили conflicting
  user values (`true/5`); без `[$i]` user values победили (`false/999`).
- Targeted builds разрешённых targets — passed.
- Targeted CTest: 9/9 passed, включая KDE/GNOME system backends, screenlock,
  session/reconciler, platform resolver/profile и static contracts.
- Negative controls: без `[$i]`, без session `Lock=true`, без KDE contribution
  и с KDE=`SessionOnly` — соответствующие tests ожидаемо failed; после
  восстановления targeted suite passed.
- Full CTest без full build: 77 passed, 4 skipped, 2 sandbox-only failures;
  оба (`session_event_server_tests`, `mode_and_owner_tests`) повторены вне
  sandbox и passed 2/2.
- Полная сборка проекта НЕ запускалась по явному ограничению задачи.

## Remaining

- Live Plasma session не была доступна; current-session behavior проверен fake
  backend test и существующими reconciliation contracts.
