# FIC: передача контекста

## Current base

- Ветка `main`, база текущей правки
  `98c09ccc247c4395c26d39a66ea2e9dfec1b49b5`.

## Current task

- Привести global DE reconciliation к общей семантике FIC:
  disabled policy становится unmanaged и не вызывает cleanup/rollback.

## Accepted architecture / invariants

- `DesktopGlobalConfigReconciler` строит только active requirements enabled
  policies. Identity остаётся `(backend, setting)`.
- Same-value requirements объединяются; differing values fail Stage A до
  любого вызова backend.
- Owners — transient metadata для merge/validation/diagnostics. Backend
  получает только physical setting/value и не хранит owners.
- `DesktopSystemBackend` обеспечивает active requirements через
  `ensureManagedSettings()` и проверяет effective protected state через
  `verifyManagedSettings()`.
- Пустой набор requirements не передаётся backend. Отсутствие setting не
  означает deletion: disable/remove оставляет фактическое состояние без
  изменений.
- Stage B обрабатывает backends независимо и агрегирует ошибки. Rollback,
  provenance, baseline restoration и uninstall cleanup не проектируются.
- Реальных GNOME/KDE/XFCE/FLY global backends пока нет; `screenlock_timeout` и
  `disable_kde_lock_screen_media_controls` остаются `SessionOnly`.

## Completed / Changed areas

- Обновлены модели и backend API `DesktopGlobalConfigReconciler`.
- Fake backend и regressions проверяют ensure-only contract, effective-state
  verification, disable/no-op, value update, conflicts, Stage A atomicity и
  независимую обработку backends.
- Обновлён относящийся static contract test.
- Согласованы `docs/session-agent.md` и `docs/architecture-diagrams.md`.

## Validation

- Fresh configure для `ubuntu-24.04` — passed. Использованы временные
  официальные headers systemd v257.9 и установленная `libsystemd.so.0`, так как
  development package в окружении отсутствует.
- Полный build `/tmp/fic-desktop-check` — passed.
- Все 7 запрошенных DE/session tests — passed.
- Полный CTest вне sandbox: 79 passed, 1 root-only skipped, 0 failed.
- Desktop/common/platform static checks — passed.
- `git diff --check` — passed.

## Remaining

- Root-only `command_hash_batch_tests` skipped; задача его контракт не меняет.
- Реальные DE global backends и runtime validation их системных механизмов
  остаются будущей работой.
