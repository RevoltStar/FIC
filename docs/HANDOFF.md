# FIC: передача контекста

## Current base

- Ветка `main`.
- База перед текущей задачей: `e4ed26e5d2aa8cb9fcce53dd6d9b7f0492ad6e34`.

## Current task

- KDE SessionOnly runtime context: исключить false success, когда daemon-side
  KConfig tools используют другой HOME/XDG graph, чем `org.kde.screensaver`.

## Accepted architecture / invariants

- KDE и XFCE остаются `SessionOnly`; GNOME и FLY — `MandatoryGlobal`.
- Authoritative KDE context принадлежит текущему owner
  `org.kde.screensaver`, а не `fic-session-agent`.
- Bus address, executable paths, UID/GID, safe base environment и cwd задаёт
  daemon; из locker разрешены только `HOME`, `XDG_CONFIG_HOME`,
  `XDG_CONFIG_DIRS`, `KDE_SKIP_KDERC` с exact absent/empty/value semantics.
- Несколько controlled KDE sessions одного UID неоднозначны и fail closed.
- KConfig readback не доказывает cached runtime state KScreenLocker.

## Completed

- Добавлен testable `KdeScreenLockerRuntimeContextResolver`: unique D-Bus
  owner, PID/UID, trusted `/proc/<pid>/environ` read и повторная identity check.
- `KdeBackend` использует captured environment для всех KConfig reads/writes,
  вызывает `configure` на unique owner и проверяет owner после reconcile.
- `SessionCommandExecutor` получил отдельный KDE-only allowlisted set/unset API;
  обычный execution contract не расширен environment overrides.
- Inventory ambiguity передаётся в обе production reconciliation paths.
- Добавлены resolver, wrong-root, environment-shape, execution-security,
  owner-race, ambiguity, timeout-flow и architecture regressions.
- Обновлена manual Plasma validation procedure.

## Changed areas

- KDE desktop backend/runtime resolver и обе KDE SessionOnly policies.
- Session inventory metadata и daemon `session_ready` reconciliation.
- KDE-specific command environment overrides.
- Desktop/KDE unit и static tests; session-agent/architecture documentation.

## Validation

- Ubuntu 24.04 targeted configure — passed.
- Affected targets `fic`, `kde_runtime_context_tests`,
  `session_setting_reconciler_tests`, `screenlock_timeout_global_tests`,
  `session_aware_policy_tests` — built successfully.
- Targeted CTest subset — 5/5 passed.
- Шесть required negative controls дали ожидаемые падения: missing
  `XDG_CONFIG_HOME`, synthetic graph, allowed `LD_PRELOAD`, removed repeat
  owner check, accepted same-UID ambiguity, KDE `MandatoryGlobal`.
- `git diff --check` — passed.
- Полная сборка проекта не запускалась по ограничению задачи.

## Remaining

- Automated tests не заменяют manual validation внутри реальной Plasma
  session с custom `plasma-workspace/env/*.sh`.
