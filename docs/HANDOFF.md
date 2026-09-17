# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `f5ba640` («Упрощаем apply/rollback для ssh»).
  Рабочее дерево содержит hardening-pass по SSH managed blocks (незакоммичен).

## Current task

- Hardening-pass SSH apply/rollback: строгая grammar FIC-маркеров,
  симметричный провенанс disabled wrappers, orphan-check до compliance
  fast-path, byte-exact cleanup собственных артефактов.

## Accepted architecture / invariants

- **Managed blocks / transaction**: все FIC-мутации sshd_config идут через
  FIC-managed block + `runSshConfigTransaction` (CAS write, durability,
  postcondition, hooks). `SshConfigFileHandler::setValue` — осознанный stub.
- **Строгая grammar (fail closed)**: внутри `FIC_SSH_BLOCK` — только
  `FIC_POLICY_BEGIN/END` sub-blocks, никаких посторонних/пустых строк; внутри
  policy sub-block — ровно одна active directive; внутри `FIC_DISABLED` —
  только один `FIC_DISABLED_LINE`. Нарушение = Malformed → conflict, файл не
  изменяется. При создании managed block FIC не добавляет separator-строку
  вне блока (byte-exact rollback).
- **Симметричный провенанс**: `checkSshDisabledProvenance` (SshManagedBlock)
  — expected wrapper IDs (journal payload) == actual (файл) как множества,
  без дубликатов с обеих сторон; используется и в `analyzeOwnership`
  (apply), и в rollback. Ничего не owned (нет блока и wrappers) — легитимный
  NothingToDo/ discard prepared путь. Malformed payload → conflict.
- **Orphan-check до fast-path**: parse модели + проверка orphan-маркеров
  выполняются в `Ssh::apply()` ДО compliance fast-path; malformed/orphan
  ownership не проходит через compliant значение.
- Malformed FIC-маркеры в rollback классифицируются как `Conflict`
  (`SshConfigFileHandler::lastLoadMarkerMalformed()`), не как Failed.
- **Mutation ID**: `FIC-<sec>-<nsec>-<pid>-<counter>-<ordinal>` — уникальность
  при рестарте процесса в ту же секунду.
- **Journal load lifecycle / virgin bootstrap** (docs/rollback.md —
  authoritative): без изменений.

## Completed

- `SshManagedBlock.*`: строгий parser (malformed на посторонние строки во
  всех owned ranges), `checkSshDisabledProvenance`/`describeSshDisabledProvenance`,
  удалён separator `""` при создании блока, усилен `generateSshDisabledMutationId`.
- `SshRollback.cpp`: симметричная проверка провенанса до любых изменений;
  conflict при malformed-маркерах.
- `Ssh.cpp`: `analyzeOwnership` через общий helper; orphan-check перенесён
  перед compliance fast-path.
- `SshConfigFile.*`: флаг `lastLoadMarkerMalformed()`.
- Тесты: 9 новых regression-тестов (A–J) в `SshApplyRollbackTests.cpp`
  (итого 24), byte-exact assertions в Match- и rollback-тестах;
  `RollbackExecutorTests`: malformed markers → Conflict.

## Changed areas

- `fic/src/modules/net/ssh/` (`Ssh.cpp`, `SshManagedBlock.*`, `SshRollback.cpp`,
  `SshConfigFile.*`)
- `tests/fic/modules/net/ssh/SshApplyRollbackTests.cpp`,
  `tests/fic/rollback/RollbackExecutorTests.cpp`

## Validation

- Full build `build-check` (ubuntu-24.04): exit 0.
- Full CTest: 96/96 passed (1 pre-existing skip `command_hash_batch_tests`).
- `ssh_apply_rollback_tests`: 24/24 PASS; `rollback_executor_tests`: 46 PASS;
  `mutation_journal_tests`: 53 PASS; `ssh_runtime_tests`: exit 0.
- `bash scripts/run-development-checks.sh fast`: exit 0.
- `git diff --check`: passed.
- ASan/UBSan: профиль проектом не предусмотрен — не запускалось.

## Remaining

- Residual TOCTOU между re-proof и fsync — known MVP limitation.
- Рабочее дерево содержит незакоммиченный diff (managed blocks +
  hardening-pass) — требуется review и коммит.