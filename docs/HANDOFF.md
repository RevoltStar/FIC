# FIC: передача контекста

## Current base

- Ветка `main`, родитель текущей правки `1650634`.

## Current task

- Завершить общий lifecycle DE-политик: корректный targeted
  `MandatoryGlobal` и declarative cleanup FIC-owned global configuration.

## Accepted architecture / invariants

- Normal apply и `session_ready` используют одну последовательность
  `ensureGlobalState`: value, protection, verify, затем runtime convergence.
- После доказанного MandatoryGlobal state runtime failure является WARN;
  SessionOnly failure, Unsupported и global failure являются ERROR.
- `DesktopGlobalConfigReconciler` собирает contributions только enabled
  policies и заменяет/проверяет только FIC-owned namespace backend-а.
- Reconcile запускается после успешного registry rebuild на startup/periodic,
  explicit apply/reload и config mutations; поэтому stale state удаляется и
  после disable, и после restart.
- Реальные system-wide GNOME/KDE/XFCE/FLY backends пока не реализованы.
  `screenlock_timeout` и `disable_kde_lock_screen_media_controls` остаются
  `SessionOnly`.

## Completed / Changed areas

- `SessionAwarePolicy::reconcileSession` возвращает явный typed result.
- Targeted MandatoryGlobal выполняет и проверяет global phases до session.
- Добавлены contribution/backend/reconciler contracts и daemon lifecycle.
- Добавлены regression tests и static contract checks; обновлены session и
  architecture docs.

## Validation

- Fresh Ubuntu 24.04 configure: passed с временным `/tmp` libsystemd compile
  shim, поскольку в окружении нет development package.
- Targeted build `session_aware_policy_tests`,
  `desktop_global_config_reconciler_tests`, `fic`: passed.
- Полный build всех targets: passed.
- Targeted final contract tests: 3/3 passed.
- Полный non-root CTest вне sandbox: 79/79 passed, включая все требуемые
  DE/session tests и `session_event_server_tests`.
- `git diff --check`: passed.

## Remaining

- Создать один итоговый commit.
- Root-only `command_hash_batch_tests` не запускался: задача не затрагивает
  command hash lifecycle.
