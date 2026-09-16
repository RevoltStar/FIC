# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `ee08cd1a4778cb925a107ce1d176bdcb23a9389d`
  (follow-up №3 к persistent rollback SSH).
- Изменения follow-up №4 закоммичены данным commit'ом (форма записи без SHA —
  SHA фиксируется историей git).

## Current task

- Follow-up №4 к persistent rollback `NET/SshEdit`: Prepared + AFTER
  postcondition через `verifyPolicyValue()`, семантика `installed !=
  durable` (`AtomicWriteResult.durabilityConfirmed`), recovery durability
  barrier (`ensureTargetDurable`), durability-гейты в SSH apply compensation
  и rollback, `MutationJournal::persist()` с post-rename durability
  handling и fail-closed `JournalHealth::Indeterminate`.

## Accepted architecture / invariants

- **installed != durable**: `rename` → `installed=true`; parent directory
  fsync → `durabilityConfirmed=true`. Journal status не переводится в
  resolved state без подтверждённой durability persistent system state.
- `AtomicWriteResult`/`FileSaveOutcome` несут `durabilityConfirmed`;
  `ensureTargetDurable(path)` — recovery-барьер (fsync parent dir, файл не
  трогает); `targetStateMatches()` re-prove ownership перед барьером;
  test seam `setDirectoryFsyncHookForTests` покрывает и barrier fsync.
- Prepared recovery: AFTER → `verifyPolicyValue(recorded parameter, recorded
  appliedValue)` → durability barrier → reload → commit Applied; BEFORE →
  validate → durability barrier → reload → discard → fresh apply; drift →
  conflict fail closed. Файл при recovery не перезаписывается.
- SSH apply/rollback: reverse-запись с non-durable rename не Success —
  `ensureSshConfigDurableIfCurrentState()` (targetStateMatches +
  ensureTargetDurable), при провале fail closed, запись активна.
  Компенсация (`SshRestoreOutcome`) доказана только при installed + durable
  + validate + reload; иначе Prepared остаётся.
- `MutationJournal::persist()` — tri-state: NotInstalled (in-memory откат
  безопасен), Persisted, Indeterminate (post-rename durability не
  подтверждена: сначала transparent finish durability, иначе журнал
  poisoned: все mutation ops отказываются; успешный `load()` возвращает
  Healthy). Порядок journal write сохранён: temp write → temp fsync →
  rename → parent fsync (без WAL/SQLite).
- Undo payload: `UndoRestoreSshDirective{parameter, appliedValue,
  occurrences}`, где `occurrences` — `SshDirectiveOccurrenceMutation
  {beforeLine, afterLine}` (нормализованный keyword; `beforeLine=null` —
  строка вставлена FIC). Порядок вектора полностью выражает identity.
  Одинаковые `afterLine` валидны. Payload self-contained, без full-file
  snapshot.
- Classification — ordered mutation-local projection (общий статик
  `classifyLinesAgainstMutation`); repeated apply через
  `matchRecordedMutationForRepair` (untracked occurrence → fail closed);
  BEFORE ≠ сразу `NothingToDo` (runtime reconciliation + durability barrier);
  компенсация — conditional restore по exact FIC-installed state;
  `Ssh::apply()`: journal lookup ДО compliance, Prepared recovery до
  fast-path; active value change fail closed; plan identity preflight
  (`validatePlannedRollbackIdentity`).
- Legacy journal форматы (`fingerprint`/`reverse_edits`) отвергаются fail
  closed; historical SSH record resolved только при `RolledBack`/`Detached`.
- Legacy (нет journal-записей): директива в global section → `Unsupported`;
  отсутствует → `NothingToDo`. Enrollment `NET/SshEdit` — только explicit
  whitelist.

## Completed

- fic-core: `AtomicWriteResult.durabilityConfirmed`;
  `AtomicFileWriter::ensureTargetDurable()` и `targetStateMatches()`;
  `FileSaveOutcome.durabilityConfirmed`; fsync-хук покрывает barrier.
- `Ssh::apply`: Prepared AFTER recovery через `verifyPolicyValue` +
  durability barrier; Prepared BEFORE barrier; компенсации требуют proven
  durability (`restoreWithProvenDurability`).
- `SshRollback`: `SshRestoreOutcome`; `ensureSshConfigDurableIfCurrentState`;
  durability-гейты BEFORE-recovery, reverse-записи и обеих компенсаций.
- `MutationJournal`: tri-state persist, transparent durability finish,
  `JournalHealth::Indeterminate`, guard во всех mutation ops, load()
  восстанавливает Healthy.
- Тесты новые: fic-core durability/барьер (4), MutationJournal
  post-rename durability/poison/reload (5), SSH: effective mismatch,
  unsafe Match override, Prepared AFTER/BEFORE barrier retry, rollback
  BEFORE/reverse barrier, apply compensation durability gate (всего 7).

## Changed areas

- `fic-common/fic-core/` (`AtomicFileWriter.{h,cpp}`, `FileHandler.{h,cpp}`)
- `fic/src/rollback/` (`MutationJournal.{h,cpp}`)
- `fic/src/modules/net/ssh/` (`Ssh.cpp`, `SshRollback.{h,cpp}`)
- `tests/fic/rollback/MutationJournalTests.cpp`,
  `tests/fic/modules/net/ssh/SshApplyRollbackTests.cpp`,
  `tests/common/core/fs/FileHandlerOptionsTests.cpp`
- `docs/rollback.md`

## Validation

- Full CMake build (build-check, ubuntu-24.04): exit 0.
- Full CTest: 96/96 passed (1 pre-existing env-dependent skip:
  `command_hash_batch_tests`).
- `git diff --check`: passed.

## Remaining

- Native интеграционной проверки с реальным sshd не выполнялось (sandbox);
  только fake-runner unit tests.
- Residual TOCTOU window между final check и `rename()` — known limitation
  (optimistic precondition, не filesystem CAS).
- Точный textual AFTER/BEFORE matching: любое внешнее изменение
  FIC-controlled строки даёт `Conflict` (three-way merge не реализовывался).
- Dynamic journal extension для untracked occurrences не реализован
  (conservative fail closed).
- Retarget активного SSH desired value — TODO, сейчас fail closed
  (disable → change → enable).
- Foreign-comment collision: first apply отказывается (fail closed).
- Indeterminate journal в рамках живого процесса daemon'а требует
  перезапуска/нового `load()` — явный fail-closed выбор (не mask'ится).
