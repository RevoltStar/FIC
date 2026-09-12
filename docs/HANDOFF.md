# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `34276da`.
- Рабочее дерево: изменены `tests/fic/platform/static_checks.py` и этот
  `docs/HANDOFF.md`.

## Current task

- Исправить падение GitHub Actions job `103588075313`: падал
  `platform_profile_static_checks` после изменения архитектуры
  `VerifiedProcessExecutor`.

## Accepted architecture / invariants

- `VerifiedProcessExecutor` сохраняет trusted executable/hash модель:
  executable открывается один раз через validated fd, SHA-256 считается по этому
  fd, затем тот же fd передаётся в `ProcessExecutor::executeImpl()`.
- Hashing должен быть offset-neutral (`pread()`), чтобы проверенный fd не
  оставался на EOF после вычисления SHA-256.
- Verified execution использует systemd-style стратегию: сначала fd-exec через
  `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` при сохранённом `CLOEXEC`;
  только при `ENOENT` выполняется checked pathname fallback через
  `execve(original_path, ...)`.
- Перед pathname fallback путь должен всё ещё указывать на тот же `st_dev/st_ino`,
  что и verified fd; replacement race fail-closed.
- Старый путь `ENOENT -> clear FD_CLOEXEC -> retry fexecve()` не является
  допустимым контрактом.

## Completed

- `platform_profile_static_checks` обновлён под новый контракт:
  `pread()` вместо `read()` для hash path и `execveat -> ENOENT -> checked
  execve(path)` вместо старого `fexecve`/clear-`FD_CLOEXEC` ожидания.

## Changed areas

- `tests/fic/platform/static_checks.py`
- `docs/HANDOFF.md`

## Validation

- `python3 tests/fic/platform/static_checks.py .` passed.
- `ctest --test-dir build-fix -R '^platform_profile_static_checks$' --output-on-failure` passed: 1/1 test.

## Remaining

- Full build/full CTest не запускались.
