# FIC: передача контекста

## Current base

- Ветка: `main`.
- HEAD до текущих незакоммиченных изменений: `1bf2477`.

## Current task

- Исправлены два unrelated existing test failure:
  `ipc_protocol_validation_tests` и `path_layout_static_checks`.

## Accepted architecture / invariants

- IPC validation tests используют `fic::ipc::API_VERSION`, production IPC
  contract не менялся.
- Obsolete-layout static checks анализируют только Git-tracked paths; required
  layout и остальные runtime/packaging проверки по worktree сохранены.

## Completed

- Current-version IPC request строится с `API_VERSION`, unsupported request —
  с `API_VERSION + 1`; deep JSON также не содержит hardcoded API version.
- `static_checks.py` один раз получает `git ls-files -z`; forbidden layout и
  nested `submodules` проверяются только среди tracked paths. Ошибка Git
  завершается понятной диагностикой.

## Changed areas

- `tests/common/ipc/IpcProtocolValidationTests.cpp`.
- `tests/common/static_checks.py`.

## Validation

- `ipc_protocol_validation_tests` target успешно пересобран.
- Targeted CTest: 2/2 passed (`ipc_protocol_validation_tests`,
  `path_layout_static_checks`).
- Прямой запуск `python3 tests/common/static_checks.py .` passed.
- `git diff --check` passed.

## Remaining

- Нет незавершённой работы в scope двух тестов.
