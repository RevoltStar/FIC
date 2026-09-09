# FIC: передача контекста

## Current base

- Ветка `main`, база текущей правки `126a8de6964e16f12831d4969f43d513f0fb93eb`.

## Current task

- Исправить physical setting identity и независимую обработку backends в
  `DesktopGlobalConfigReconciler`.

## Accepted architecture / invariants

- Identity — `(backend, setting)`; значение и множество `PolicyRef` owners
  хранятся отдельно. Одинаковые значения объединяют owners. Отключение одного
  owner сохраняет настройку, последнего — удаляет FIC-managed entry.
- Stage A полностью проверяет enabled contributions, capability/interface,
  backend, producing owner и conflicts до любых backend mutations.
- Stage B независимо обрабатывает каждый backend: read, conditional replace,
  exact readback verification значения и owners. Все ошибки агрегируются с
  именами backends; любая ошибка сохраняет общий failure.
- Между backends нет общей транзакции. Foreign administrator state остаётся
  вне managed namespace и не изменяется framework-ом.
- Реальных GNOME/KDE/XFCE/FLY system backends пока нет. Production policies
  остаются SessionOnly; policy-level MandatoryGlobal lifecycle не менялся.

## Completed / Changed areas

- Исправлены модели и обе стадии `DesktopGlobalConfigReconciler.{h,cpp}`.
- Расширен `DesktopGlobalConfigReconcilerTests.cpp`: shared ownership, disable,
  conflicts (включая одну policy), Stage A validation, независимые namespaces,
  backend failures/readback и aggregation, сохранение foreign state.
- Согласованы `docs/session-agent.md` и `docs/architecture-diagrams.md`.

## Validation

- Fresh configure: `PKG_CONFIG_PATH=/tmp/fic-systemd-dev/pkgconfig cmake --fresh
  -S . -B /tmp/fic-desktop-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` — passed.
  В окружении отсутствует libsystemd development package: использованы
  официальные headers systemd v257.9 в `/tmp` и настоящая установленная
  `libsystemd.so.0` той же версии; stub functions не использовались.
- Target build `desktop_global_config_reconciler_tests` и полный
  `cmake --build /tmp/fic-desktop-check -j2` — passed.
- Targeted CTest: все 7 DE/session targets из задания — passed.
- Полный `ctest --test-dir /tmp/fic-desktop-check --output-on-failure` вне
  sandbox — 79 passed, 1 skipped, 0 failed (80 зарегистрированных tests).
- Python static checks: desktop_environment, common и platform — passed;
  полный CTest также выполнил 15 static tests.
- Negative controls: отключение conflict check и возврат backend fail-fast
  по отдельности приводят к ожидаемому падению regression tests.
- `git diff --check` — passed.

## Remaining

- Root-only `command_hash_batch_tests` skipped; host security state не менялся.
- Реальные DE system backends не реализованы и runtime-проверка их поведения
  не входит в эту задачу.
