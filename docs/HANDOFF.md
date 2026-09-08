# FIC: передача контекста

## Current base

- Ветка `main`, commit `3d6887a` (Исправляем зависание ProcessExecutor после
  timeout/output-limit).
- Незакоммиченная правка поверх него: только
  `tests/common/core/process/ProcessOutputLimitTests.cpp`.

## Current task

- Test-only fix: детерминированная проверка гибели descendant-процесса в
  `process_output_limit_tests`. Ранее `assertDescendantKilled` ждал любого
  потомка через `waitpid(-1, ..., WNOHANG)` и дополнительно требовал
  `waitpid(-1) == -1 && errno == ECHILD` — на CI это падало: убитый член
  process group может остаться transient zombie между SIGKILL и recom'ом, и
  глобальный probe ловит ECHILD слишком рано.

## Accepted architecture / invariants

- Инварианты ProcessExecutor/ProcessPipeIo (interruptible I/O, group kill,
  cancel semantics) — без изменений; production-код не менялся.
- Паттерн из `ProcessCancellationTests.cpp`: fixture-потомок публикует свой
  PID в pid file до ready-token; тест, будучи `PR_SET_CHILD_SUBREAPER`,
  детерминированно делает `waitpid(<конкретный PID>, ...)` и проверяет
  SIGKILL. Глобальные `waitpid(-1)`-пробы в этом тесте больше не используются.

## Completed / Changed areas

- `tests/common/core/process/ProcessOutputLimitTests.cpp`:
  `fixture(mode, bytes, pidFile)` — descendant пишет PID в pidFile перед
  ready-байтом; `assertDescendantKilled(pidFile)` ждёт именно этот PID;
  хрупкая проверка `waitpid(-1) == -1 && errno == ECHILD` удалена; PID file
  живёт на уровне итерации `verified` (перезаписывается каждым descendant-режимом).

## Validation

- `process_output_limit_tests` (обычный билд `/tmp/fic-dev-build`): 40
  прогонов подряд подряд — 0 падений (раньше падение было race-зависимым на CI).
- Sanitizer-конфигурация как в CI (`-fsanitize=address,undefined`,
  ASAN_OPTIONS detect_leaks=1:halt_on_error=1, UBSAN halt_on_error=1):
  `/tmp/fic-san-build`, полный build success (72 targets, 0 errors),
  `ctest -L '^unit$'` — 53/53 passed (в т.ч. process_output_limit_tests и
  process_cancellation_tests).
- Обычный полный CTest: 77/77 passed; `git diff --check` clean.
- Build использует stub libsystemd (`PKG_CONFIG_PATH=/tmp/fic-dev-tree/pkgconfig`)
  — вне git.

## Remaining

- Не проверялось: запуск в GitHub Actions CI (упавшая среда воспроизводила
  race реже локальной; fix устраняет сам race в probe, а не его тайминг).
- Коммит не создавать без отдельного запроса пользователя.