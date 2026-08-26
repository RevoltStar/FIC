# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `e190798f716384aa4383664ff98db7fd8fbf1034`.

## Current task

- Исправление ложной числовой валидации строковых политик USER_CREATION в GUI.

## Accepted architecture / invariants

- `PolicyEditorSpec.editor` определяет только вид GUI-контрола.
- `PolicyEditorSpec.validator` независимо определяет клиентскую валидацию:
  `none`, `integer_range`, `unsigned_integer` или `allowed_values`.
- Daemon остаётся authoritative источником окончательной policy validation.
- Administrative IPC API остаётся version `1`; `validator` является добавочным
  полем ответа `policy_list`.

## Completed

- Daemon добавляет `validator` в каждый `policy_list` descriptor.
- GUI разбирает и проверяет явный validator вместо вывода типа значения из
  `lineedit`.
- Пути, shell и имя primary group принимаются как строки; UID policies
  сохраняют unsigned-integer validation.
- Добавлены descriptor и concrete-policy regression tests, обновлена IPC
  документация поля `validator`.

## Changed areas

- `fic-common/fic-policy/`, `fic/src/main.cpp`;
- `fic-gui/src/features/policies/`;
- IPC descriptor docs и relevant GUI, user-creation, password-aging tests.

## Validation

- `cmake -S . -B /tmp/fic-architecture-build -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build /tmp/fic-architecture-build -j2` — успешно.
- Targeted descriptor, GUI static, policy service, user-creation и
  password-aging tests — успешно.
- Финальные targeted tests: 7/7 успешно, включая version contract, GUI static,
  descriptor/service, user-creation и password-aging tests.
- Полный CTest с IPC API version `1`: 40 passed, 4 skipped, 2 unrelated
  failures — `platform_profile_static_checks` (ALT p11 packaging omits
  `--maintenance wait-daemon 10`) и существующий
  `ipc_protocol_validation_tests` assertion.
- `git diff --check` — успешно.

## Remaining

- Для проверки на `10.88.0.250` необходимо собрать и установить обновлённые
  daemon и GUI; runtime deployment не выполнялся.
- Unrelated ALT p11 packaging и IPC protocol test failures оставлены без
  изменений.
