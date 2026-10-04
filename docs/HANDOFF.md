# FIC handoff

## Current base

* branch: `main`
* base commit: `8f53a32` + SUDO hardening (include lexer, scoped Defaults
  blocker, `sudo_exempt_group_disable`, reverse-dependency guard)

## Current task

Hardening подсистемы SUDO: корректный разбор include-директив, запрет
контекстных (scoped) `Defaults` отдельной политикой с ownership/rollback
моделью, выделение `exempt_group` в отдельного владельца. Выполнено.

## Accepted architecture / invariants

* Include-подграмма разбирается специализированным лексером
  `SudoersIncludeDirective`: директива распознаётся ДО обработки комментариев
  (`#` — одновременно начало комментария и часть legacy `#include`).
  Поддержаны `"..."`, экранирование пробелов и обратного слэша, trailing
  inline-комментарий, относительный pathname, continuation. Неподдерживаемое и
  неоднозначное — явный fail-closed, НЕ silent ignore (тихий пропуск сузил бы
  активно подключённый граф). `%`-подстановки остаются fail-closed.
* Две НЕСМЕШИВАЕМЫЕ модели владения SUDO: managed scalar Defaults
  (`zzzz-fic`, значение ключа) и source-edit wrapper (`sudo_disable_scoped_defaults`).
* `sudo_disable_scoped_defaults`: запрещены все четыре scope (`:`, `@`, `>`, `!`).
  Детекция строго синтаксическая — алиасы/`%group`/netgroups/отрицание НЕ
  вычисляются, само наличие scoped-записи является нарушением.
* Обёртки `#@FIC_SUDO_DISABLED_*` — собственный namespace SUDO (SSH-маркеры не
  переиспользуются). Исходные байты живут внутри обёртки; journal payload —
  только policy identity + wrapper ids (доказательство разрешения, не бэкап).
  Snapshot всего `/etc/sudoers` не используется.
* Crash-consistency apply-транзакции НЕ заявляется: восстановление — это
  `Prepared`-запись журнала, подготовленная ДО файловой мутации; wrapper ids
  генерируются до journaling, поэтому payload сразу полный.
* `exempt_group` имеет ровно одного владельца — `sudo_exempt_group_disable`.
  `sudo_require_authentication` больше не переписывает `exempt_group`.
* Обратная защита: обязательная зависимость включённой политики не отключается
  раньше неё (`enabledRequiredDependents` в `PolicyDependencyGraph`). Без
  скрытого cascade-disable.

## Completed

* Новые компоненты: `SudoersIncludeDirective`, `SudoersScopedDefaults`,
  `SudoersDisabledWrapper` + новые политики `sudo_disable_scoped_defaults`,
  `sudo_exempt_group_disable`.
* `MutationRecord`/`MutationJournal`/`RollbackExecutor`: payload
  `UndoReleaseSudoScopedDefaults`, whitelist enrollment без default-positive,
  orphan-обёртка без активной записи журнала → fail closed.
* Зависимости и обратный guard; регрессии в
  `SudoersConfigurationTests`, `PolicyExecutionPlannerTests`,
  `RollbackExecutorTests`.

## Changed areas

* `fic/src/modules/dac/sudo/*` (backend, две новые политики)
* `fic/src/rollback/{MutationRecord.h,MutationJournal.cpp,RollbackExecutor.cpp}`
* `fic/src/policy/execution/PolicyDependencyGraph.*`,
  `fic/src/daemon/main_function.cpp`
* `docs/{rollback.md,architecture-diagrams.md}`, `resources/{config,lang}`

## Validation

* `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04`
* `cmake --build build-check -j4` — RC=0
* `ctest --test-dir build-check --output-on-failure` — 117/117 PASS
  (`command_hash_batch_tests` — Skipped, не связан с задачей)
* `visudo-rs 0.2.13` использован как oracle для синтаксиса обёрток и
  подтверждения, что FIC-комментарии остаются валидным sudoers.

## Remaining

* Полный E2E с реальным применением политик на хосте не запускался (unsafe
  runtime validation по AGENTS.md).
* `+=`/`-=` для существующих четырёх scalar-политик сознательно не реализованы:
  подтверждённого false-positive под задачу нет.
* `%h`-подстановка в include остаётся fail-closed намеренно.
