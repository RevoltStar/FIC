# FIC: передача контекста

## Current base

- Ветка `main`, база текущей правки
  `a8b579094fe162dab0359b4b08de7989d059a0a4` (policy-level hooks удалены).

## Current task

- Ввести структурированный результат global reconciliation
  (`DesktopGlobalReconcileReport`) вместо общего bool, чтобы normal apply,
  targeted `session_ready`, `apply_policy` и `apply_module` определяли
  global enforcement per policy/per desktop/per backend.

## Accepted architecture / invariants

- `DesktopSystemBackend` остаётся единственным global enforcement path;
  policies только публикуют requirements через `GlobalDesktopPolicyContributor`.
- Contribution несёт typed desktop association
  (`GlobalDesktopPolicyContribution::desktop`); desktop НЕ выводится из имени
  backend. Physical identity — по-прежнему `(backend, setting)`.
- `DesktopGlobalConfigReconciler::reconcile()` возвращает
  `DesktopGlobalReconcileReport` (bool-only API удалён):
  - `requirementsValid` + `stageADiagnostic` (Stage A fail-closed, без
    backend mutation);
  - `backends[backend] = {attempted, verified, diagnostic}` — независимые
    per-backend результаты;
  - `policies[PolicyRef][DesktopEnvironmentKind] =
    PolicyGlobalEnforcementResult{hasRequirement, verified, backends,
    diagnostic}`; shared same-value settings дают обоим owners один backend
    result.
- Stage A инварианты: конфликт values, unknown backend, invalid owner/key,
  unknown desktop, capability/contributor mismatch, `MandatoryGlobal`
  (policy, desktop) без contribution coverage, contribution для
  `SessionOnly`/не-applicable desktop — все fail-closed, mutation не
  происходит.
- Политика сессии получает `resultFor(policy, session.desktop)`;
  `SessionOnly` от global report не зависит. Для `MandatoryGlobal` verified
  global state + session prepare/runtime failure = warning
  (`MandatoryGlobalRuntimeWarning`), не `GlobalEnforcementFailed`.
- Normal apply: daemon устанавливает report в каждую session-aware policy
  через `setGlobalEnforcementResults()` (Option B: per-pass explicit context,
  без singleton/static state); policy apply fails при missing coverage или
  failed relevant backend; `globallyEnforced` наполняется только из
  structured results.
- `apply_all`/startup — overall failure при любом backend failure;
  `apply_policy`/`apply_module` — policy/module-scoped success
  (`successfulForPolicy`/`successfulForModule`), unrelated backend failure
  не отвергает успешный targeted request.
- `DISABLE` не публикует requirements и не вызывает backend cleanup;
  rollback/provenance по-прежнему вне scope.
- Production GNOME/KDE/XFCE/FLY global backends пока не реализованы.

## Completed / Changed areas

- `fic/src/modules/oss/desktop_environment/`:
  structured report API, Stage A coverage invariants,
  `SessionAwareDesktopEnvironmentPolicy` (per-desktop global results,
  warning semantics, normal apply consumption).
- `fic/src/main.cpp`: report установлен в policies на каждом pass
  (`install_desktop_global_report`); `reconcile_session_ready` передаёт
  policy-specific result; `apply_all`/`apply_module`/`apply_policy` —
  scoped report success.
- Tests: `DesktopGlobalConfigReconcilerTests` (per-backend, shared owners,
  failure isolation, coverage, SessionOnly cases),
  `SessionAwarePolicyTests` (normal apply, targeted path, prepare warning,
  mixed DE), `static_checks.py.in` (structured report, отсутствие
  bool-contract, отсутствие unconditional `globallyEnforced.insert`).
- Docs: `session-agent.md`, `architecture-diagrams.md` — structured report
  contract.

## Validation

- Fresh configure `ubuntu-24.04` с `PKG_CONFIG_PATH=/tmp/fic-systemd-dev`
  (временные официальные headers systemd v257.9) — passed.
- Полный build `build-check` — passed (75 targets, без ошибок).
- 7 targeted DE/session tests — passed.
- Полный ctest: 80 passed, 0 failed; root-only `command_hash_batch_tests`
  skipped (вне sandbox, contract не затронут).
- `git diff --check` — passed.

## Remaining

- Реальные GNOME/KDE/XFCE/FLY system backends не реализованы (следующий этап:
  первый production `GnomeSystemBackend`).
- Root-only `command_hash_batch_tests` skipped.

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
