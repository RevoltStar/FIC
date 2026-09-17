# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `7544a0baaad6ae89787dd579c56a7301efe1c061`
  (follow-up №8+ к persistent rollback SSH; рабочее дерево содержит большой
  незакоммиченный рефакторинг SSH apply/rollback: managed blocks +
  `SshConfigTransaction` + CAS-запись).

## Current task

- Рефакторинг SSH apply/rollback (managed-block architecture) + ремонт
  тестовой обвязки `ssh_apply_rollback_tests` до полностью зелёного состояния.

## Accepted architecture / invariants

- **Managed blocks / transaction**: все FIC-мутации sshd_config идут через
  FIC-managed block (BEGIN/END маркеры) + `runSshConfigTransaction`
  (CAS write по snapshot из `loadConfig`, durability, postcondition, hooks).
  Прямое глобальное переписывание через `SshConfigFileHandler::setValue`
  отказано (stub возвращает false) — legacy test обновлён соответственно.
- **Reload после rollback внутри apply**: при value change откат предыдущего
  состояния выполняется отдельным handler'ом; после него основной
  `sshConfig_` обязан сделать `loadConfig()` повторно, иначе CAS-запись
  нового состояния отклоняется (фикс в `Ssh.cpp`, блок после
  `activeRecords.clear()`).
- **Journal load lifecycle / virgin bootstrap** (docs/rollback.md —
  authoritative): см. предыдущие follow-up'ы — без изменений.

## Completed

- `SshApplyRollbackTests.cpp`: `PolicyUnderTest` вынесен в namespace scope
  (разрешён use-before-declaration), `makePolicy()` инлайнен в классе;
  debug-хелперы `requireApply`/`requireNotApply`; value-change тест создаёт
  свежую политику после смены конфига (moduleConf кэшируется в ctor);
  multi-policy тест пишет общий NET.conf вместо двух `writePolicyValue`.
- `Ssh.cpp`: reload конфига после value-change rollback (см. инвариант).
- `tests/CMakeLists.txt`: в `ssh_runtime_tests` добавлен `SshRollback.cpp`
  (нужен после появления вызовов rollback-функций в `SshConfigTransaction`).
- `SshRuntimeTests.cpp`: legacy-тест прямой записи глобального значения
  переписан под отказ `setValue` (см. инвариант).

## Changed areas

- `fic/src/modules/net/ssh/` (`Ssh.cpp`, новые `SshConfigTransaction.*`,
  `SshManagedBlock.*`, `SshRollback.*`, `SshConfigFile.*`)
- `fic/src/rollback/` (`MutationJournal`, `RollbackExecutor`, `MutationRecord`)
- `tests/fic/modules/net/ssh/`, `tests/fic/rollback/`, `tests/CMakeLists.txt`

## Validation

- Full build `build-check` (ubuntu-24.04): exit 0.
- Full CTest: 96/96 passed (1 pre-existing skip `command_hash_batch_tests`).
- `ssh_apply_rollback_tests`: 15/15 PASS.
- `bash scripts/run-development-checks.sh fast`: exit 0 (81/81).
- `git diff --check`: passed.

## Remaining

- Residual TOCTOU между re-proof и fsync — known MVP limitation.
- Удаление обоих файлов внешним actor'ом — принятое ограничение модели.
- Рабочее дерево содержит большой незакоммиченный diff — требуется review
  и коммит.