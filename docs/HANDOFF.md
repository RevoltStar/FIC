# FIC: передача контекста

## Current base

- Ветка `main`, база текущей правки
  `fa5da390934eefd454cb6ea549006f778775b540`.

## Current task

- Удалить policy-level global enforcement hooks и сделать
  `DesktopSystemBackend` единственным global enforcement path для normal apply
  и targeted `session_ready`.

## Accepted architecture / invariants

- Policies описывают active global requirements через
  `GlobalDesktopPolicyContributor`; они не применяют value/protection и не
  выполняют global verification самостоятельно.
- `DesktopGlobalConfigReconciler` валидирует requirements, затем вызывает
  `DesktopSystemBackend::ensureManagedSettings()` и
  `verifyManagedSettings()`; это единственный механизм global enforcement.
- Normal daemon apply выполняет global reconciler до policy apply.
- После классификации нового desktop targeted `session_ready` выполняет тот же
  registry-wide reconciler до targeted session convergence.
- Ошибка global reconciler блокирует session convergence для
  `MandatoryGlobal` и возвращает `GlobalEnforcementFailed`; `SessionOnly` от
  global result не зависит.
- После подтверждённого backend state runtime failure `MandatoryGlobal`
  остаётся warning. Production DE policies пока остаются `SessionOnly`.
- Disabled policy не участвует в requirements и не вызывает cleanup/rollback.

## Completed / Changed areas

- Удалены `ensureGlobalState`, `applyGlobalValue`, `applyGlobalProtection` и
  `verifyGlobalState` из `SessionAwareDesktopEnvironmentPolicy`.
- `SessionAwarePolicy::reconcileSession` получает результат общего backend
  pass для корректной классификации targeted result.
- `reconcile_session_ready` вызывает `DesktopGlobalConfigReconciler` один раз
  перед обходом enabled session-aware policies.
- Обновлены session policy tests, static contract checks и DE documentation.

## Validation

- Fresh configure для `ubuntu-24.04` — passed с временными официальными
  headers systemd v257.9 и установленной `libsystemd.so.0`.
- Полный build `/tmp/fic-desktop-check` — passed.
- Все 7 targeted DE/session tests — passed.
- Desktop/common/platform static checks — passed.
- Полный CTest вне sandbox: 79 passed, 1 root-only skipped, 0 failed.
- `git diff --check` — passed.

## Remaining

- Реальные GNOME/KDE/XFCE/FLY global backends ещё не реализованы.
- Root-only `command_hash_batch_tests` skipped; изменённый DE contract его не
  затрагивает.
