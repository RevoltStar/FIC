# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `a48b736`.
- Рабочее дерево: изменены `fic-common/fic-core` process/integrity paths,
  соответствующие unit tests и этот `docs/HANDOFF.md`.

## Current task

- Исправить `VerifiedProcessExecutor` для корректного запуска shebang scripts,
  включая `/usr/sbin/pam-auth-update`.

## Accepted architecture / invariants

- Root cause: verified executable fd хешировался чтением до EOF и затем этот же
  fd передавался в execution path. Для Perl/shebang scripts это могло давать
  `rc=0` без фактического выполнения тела script.
- Hashing теперь offset-neutral (`pread()`), поэтому вычисление SHA-256 не
  оставляет проверенный fd на EOF.
- Execution strategy выбрана в стиле systemd: сначала `execveat(fd, "",
  argv, envp, AT_EMPTY_PATH)` с сохранённым `CLOEXEC`; если fd-exec вернул
  `ENOENT` (типичный close-on-exec shebang case), fallback идёт через
  `execve(original_path, ...)`.
- Перед pathname fallback проверяется, что `original_path` всё ещё указывает
  на тот же `st_dev/st_ino`, что и verified fd. Если путь заменён, execution
  fail-closed.
- Старый путь `ENOENT -> clear FD_CLOEXEC -> повторить fexecve()` удалён:
  `/dev/fd/N` semantics несовместимы с программами, которые полагаются на
  корректный `$0`/pathname и делают self-reexec или helper exec как
  `pam-auth-update`/debconf.
- Существуют более hardened-варианты, позволяющие жёстче сохранять invariant
  "исполняется именно проверенный inode": private mount namespace/new mount
  API, fs-verity, IMA/appraisal и похожие механизмы. Сознательно принято
  решение не использовать эти варианты, чтобы не усложнять архитектуру
  `VerifiedProcessExecutor` и не вводить дополнительные platform/runtime
  dependencies.

## Completed

- `calculateSha256FromFd()` переведён с `read()` на `pread()` и больше не
  меняет текущий offset caller-owned fd.
- `ProcessExecutor::executeImpl()` запускает verified fd через `execveat`
  `AT_EMPTY_PATH`, сохраняет `FD_CLOEXEC`, и при `ENOENT` делает checked
  pathname fallback.
- Regression tests покрывают ELF/binary fd execution, simple shebang,
  Perl shebang, self-reexec through `$0`, pam-auth-update-like helper exec и
  replacement-race fail-closed для shebang fallback.

## Changed areas

- `fic-common/fic-core/src/integrity/CommandHashStore.cpp`
- `fic-common/fic-core/src/process/ProcessExecutor.cpp`
- `tests/common/core/integrity/CommandHashSecurityTests.cpp`
- `tests/common/core/process/VerifiedProcessExecutorTests.cpp`
- `docs/HANDOFF.md`

## Validation

- `cmake --build build-fix --target command_hash_security_tests verified_process_executor_tests -j2` passed.
- `ctest --test-dir build-fix -R '^(command_hash_security_tests|verified_process_executor_tests)$' --output-on-failure` passed: 2/2 tests.

## Remaining

- Full build/full CTest не запускались.
- Попытка свежего configure в `build-vpe-check` остановилась на отсутствующем
  локальном `gio-2.0` dev package; для targeted validation использован уже
  сконфигурированный `build-fix`.
