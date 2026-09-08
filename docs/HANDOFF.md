# FIC: передача контекста

## Current base

- Ветка `main`, commit `e33d113` (maxOutputBytes).
- До текущей задачи рабочее дерево было чистым.

## Current task

- Interruptible pipe I/O в ProcessExecutor: bounded return после timeout /
  output-limit, даже если escaped descendant (setsid) держит унаследованные
  stdin/stdout/stderr pipe descriptors открытыми.

## Accepted architecture / invariants

- Внутренняя abstraction `process_executor_detail::ProcessPipeIo`
  (`fic-common/fic-core/src/process/ProcessPipeIo.{h,cpp}`): shared
  capture/cancellation state; parent-side pipe ends nonblocking; каждый worker
  делает `poll(fd, 20ms)` в цикле с проверкой atomic `cancelled_` — нет
  busy-loop и нет бесконечного ожидания EOF/записи.
- Каждый I/O thread эксклюзивно владеет своим fd и сам его закрывает
  (`finish`); cancel не закрывает чужие descriptors → нет
  use-after-close/double close.
- `cancel()` замораживает `reason_` (Running→Cancelled CAS): overflow, уже
  зафиксированный readers, сохраняет приоритет над timeout; после cancel
  in-flight read не может превратить timeout в output-limit failure.
- Parent monitoring loop: waitid WNOWAIT удерживает leader PID; при overflow
  или timeout — group SIGKILL (fallback на PID, best-effort) + `io.cancel()`;
  loop завершается по `childExited && io.completed()`, где completed теперь
  наступает bounded по времени (≤ один 20 ms poll после cancel).
- Reader после cancel не drain-ит до EOF; writer stdin прекращает запись даже
  при живом, но не читающем потребителе. stdin не входит в output budget.
- Публичный API ProcessExecutor/VerifiedProcessExecutor не менялся; fd-bound
  fexecve и shebang retry path сохранены. Контракт maxOutputBytes прежний.
- Никаких detached threads; pthread_cancel не используется.

## Completed / Changed areas

- `fic-common/fic-core/src/process/ProcessPipeIo.{h,cpp}` (новые),
  `ProcessExecutor.cpp` (read_pipe/write_pipe заменены на ProcessPipeIo,
  parent pipe ends O_NONBLOCK), `fic-common/fic-core/CMakeLists.txt`.
- `tests/common/core/process/ProcessCancellationTests.cpp`,
  `tests/CMakeLists.txt` (target process_cancellation_tests, TIMEOUT 35):
  plain+verified × {normal, stdout-exit, stderr-exit, stdout-timeout,
  stderr-timeout, stdin-exit, overflow, flood-exit} × 2 повтора; fixture
  использует явный setsid + ready-pipe (детерминированно), тест — subreaper,
  собственный alarm(30) watchdog, cleanup escaped процессов, проверка
  отсутствия fd/thread leaks через /proc/self/{fd,task}.

## Validation

- Build `/tmp/fic-dev-build` (ubuntu-24.04, stub libsystemd в
  `/tmp/fic-dev-tree`): targeted `fic-core process_cancellation_tests
  process_output_limit_tests verified_process_executor_tests` — success.
- Targeted CTest (3 tests) — passed; полный build — success; полный CTest —
  77 passed, 1 skipped (root-only command_hash_batch_tests), 0 failed.
- `tests/fic/platform/static_checks.py`, `tests/common/static_checks.py`,
  `git diff --check` — clean.
- Логи: `/tmp/fic-cancel-{target-build,targeted-ctest,full-build,full-ctest}.log`.

## Remaining

- Незавершённых изменений по задаче нет. Podman-прогон не выполнялся
  (опциональная дополнительная validation); root-only test не запускался.
- Коммит не создавать без отдельного запроса пользователя.
