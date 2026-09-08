# FIC: передача контекста

## Current base

- Ветка: `main`, commit `532b617`.
- До текущей задачи рабочее дерево было чистым.

## Current task

- Устранение TOCTOU между hash verification и запуском в `VerifiedProcessExecutor`.

## Accepted architecture / invariants

- Validation, SHA-256 и execution привязаны к одному открытому файловому объекту.
  После verification исходный pathname используется только для argv/diagnostics.
- `CommandHashStore` отдаёт owning fd через internal helper; `ProcessExecutor`
  переиспользует общую process logic через private `executeImpl`.
  Публичный API и обычная pathname-семантика `ProcessExecutor::execute` сохранены.
- Shebang: при `ENOENT` снимается `FD_CLOEXEC` только в child, затем повторяется
  `fexecve` по тому же fd. Parent закрывает свой fd через RAII.
- Подробный контракт и ограничения: `docs/architecture-diagrams.md`, раздел
  command hashes. Защита от записи в тот же inode и проверка интерпретатора
  не входят в этот контракт; script `$0` становится fd-путём.

## Completed

- Сохранены safe open flags, fstat/type/execute-bit checks и SHA-256 по fd.
  Низкие fd перемещаются выше stdio slots до validation/hash.
- Общая fork/pipes/timeout/process groups/credentials/environment logic сохранена;
  verified branch использует только `fexecve`, без pathname fallback.
- Добавлены детерминированные regressions через test-only linker wrapping fork:
  замена binary A на B, удаление pathname, замена shebang A на B.
- Проверяются shebang, argv, stdin/stdout/stderr, empty/inherited/overridden env,
  workingDirectory, текущие uid/gid, timeout/process groups, закрытие parent fd
  при success/hash mismatch/pipe/fork/chdir/exec errors и отсутствие fd у binary.
- Обновлены непосредственно связанные static checks и архитектурное описание.

## Changed areas

- `fic-common/fic-core/{src/integrity,src/process,include/fic/core/process}`.
- `tests/common/core/process/VerifiedProcessExecutorTests.cpp`, `tests/CMakeLists.txt`,
  `tests/fic/platform/static_checks.py`.
- `docs/architecture-diagrams.md`, `docs/HANDOFF.md`.

## Validation

- Configure: `PKG_CONFIG_PATH=/tmp/fic-dev-tree/pkgconfig cmake -S . -B
  /tmp/fic-dev-build -DFIC_TARGET_PLATFORM=ubuntu-24.04`: success.
- Targeted build: `verified_process_executor_tests`, `command_hash_security_tests`,
  `calc_hash_command_tests`: success.
- Targeted CTest (эти три теста + platform/path-layout static checks): 5/5 passed.
- `python3 tests/fic/platform/static_checks.py .` и
  `python3 tests/common/static_checks.py .`: success.
- Negative controls отдельно собраны в `/tmp`: старая verified pathname-реализация
  падает на atomic replacement regression, вариант без CLOEXEC retry — на shebang.
  Production sources при этом не менялись.
- `cmake --build /tmp/fic-dev-build -j2`: success.
- `ctest --test-dir /tmp/fic-dev-build --output-on-failure`: вне sandbox
  73 passed, 1 skipped (`command_hash_batch_tests`, требует root), 0 failed.
  Первый запуск в sandbox: 3 failures (socket bind, NSS group lookup,
  corresponding-source test); вне sandbox все три прошли.
- Логи: `/tmp/fic-verified-full-build.log`,
  `/tmp/fic-verified-full-ctest-unsandboxed.log`.
- Финальный diff review выполнен; `git diff --check`: clean.

## Remaining

- Сборка использует существующий stub libsystemd в `/tmp/fic-dev-tree/*`;
  реальный systemd runtime, root-only hash batch test и смена на другие
  uid/gid/user не проверялись.
- Коммит не создавать без отдельного запроса пользователя.
