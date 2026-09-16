# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `a840283764c1ecfb183d34c386921608d40f8321`
  (follow-up №4 к persistent rollback SSH).

## Current task

- Follow-up №5 к persistent rollback `NET/SshEdit`: durability-proven
  `MutationJournal::load()` (readable != Healthy), `Indeterminate` как гейт
  ВСЕХ operational-решений через `DaemonMutationJournal::tryGet()` (lazy
  recovery, вариант A), state-bound durability-барьеры SSH recovery
  (`ensureTargetDurableIfCurrentState`) для Prepared AFTER/BEFORE и rollback
  BEFORE.

## Accepted architecture / invariants

- **Journal load**: `captureTargetState` → parse только `snapshot.content` →
  `targetStateMatches(path, snapshot)` → `ensureTargetDurable` → только потом
  publish + `Healthy`. Провал barrier/re-proof → `load()==false`, health
  `Indeterminate`, in-memory state не заменяется. Missing file — прежняя
  семантика empty provenance. Test-only seam:
  `MutationJournal::setLoadAfterCaptureHookForTests` (между capture и
  re-proof).
- **`usable() = loaded_ && Healthy`**: operational-решения (apply, rollback,
  disable ownership resolution, journal-backed detach) опираются только на
  usable-журнал; `records()/activeRecords()` — raw inspection API.
  `DaemonMutationJournal::tryGet()` возвращает journal только при `usable()`;
  иначе — lazy recovery через исправленный `load()`; неудача → `nullptr` +
  «Mutation journal is Indeterminate; successful reload or daemon restart is
  required». Мутирующие guards сохранены как defensive layer.
- **Generic `AtomicFileWriter::ensureTargetDurableIfCurrentState(path,
  expected, error)`**: targetStateMatches + fsync каталога, ошибки
  дифференцированы («state changed before durability confirmation» vs fsync
  error). Используется: journal load, journal persist transparent finish,
  SSH Prepared AFTER/BEFORE recovery (барьер привязан к exact
  `loadSnapshot()` — снимку, который классифицировал/верифицировал
  recovery), rollback BEFORE recovery (через
  `ensureSshConfigDurableIfCurrentState`). Residual TOCTOU между re-prove и
  fsync — известное MVP-ограничение (не CAS).
- **installed != durable**: `rename` → `installed=true`; parent directory
  fsync → `durabilityConfirmed=true`. `AtomicWriteResult`/
  `FileSaveOutcome` несут `durabilityConfirmed`; test seam
  `setDirectoryFsyncHookForTests` покрывает и barrier fsync.
- Prepared recovery: AFTER → `verifyPolicyValue(recorded appliedValue)` →
  state-bound durability barrier → reload → commit Applied; BEFORE →
  validate → state-bound barrier → reload → discard → fresh apply; drift →
  conflict fail closed. Файл при recovery не перезаписывается.
- SSH apply/rollback: reverse-запись с non-durable rename не Success;
  компенсации требуют installed + durable + validate + reload.
- `MutationJournal::persist()` — tri-state (NotInstalled / Persisted /
  Indeterminate); Indeterminate: in-memory = установленному документу, все
  mutation ops отказываются. Порядок journal write: temp write → temp fsync
  → rename → parent fsync (без WAL/SQLite). Схема JSON (kSchemaVersion=1)
  не менялась.
- Undo payload `UndoRestoreSshDirective{parameter, appliedValue,
  occurrences}`; classification — ordered mutation-local projection;
  repeated apply fail closed на untracked occurrences; planner→classifier
  preflight; active SSH retarget fail closed; legacy форматы отвергаются.
- Legacy (нет journal-записей): global-section директива → `Unsupported`;
  отсутствует → `NothingToDo`. Enrollment `NET/SshEdit` — explicit
  whitelist.

## Completed

- fic-core: `ensureTargetDurableIfCurrentState()`.
- `MutationJournal::load()`: snapshot-bound + durability barrier, poisoning
  при провале; `usable()`; test-only load-after-capture hook.
- `DaemonMutationJournal::tryGet()/open()`: health-gate + lazy recovery.
- SSH: Prepared AFTER/BEFORE recovery и rollback BEFORE recovery привязаны
  к exact classified snapshot; persist transparent finish через новый helper.
- Тесты новые: journal load barrier fail+retry, load race capture↔barrier,
  daemon tryGet gate/lazy recovery, rollback fail closed на Indeterminate
  journal, SSH apply blocked, Prepared AFTER/BEFORE и rollback BEFORE при
  внешнем replacement (5+4+1=10 новых проверок); обновлены 2 существующих
  journal-теста под новую семантику Healthy.

## Changed areas

- `fic-common/fic-core/` (`AtomicFileWriter.{h,cpp}`)
- `fic/src/rollback/` (`MutationJournal.{h,cpp}`, `DaemonMutationJournal.{h,cpp}`)
- `fic/src/modules/net/ssh/` (`Ssh.cpp`, `SshRollback.cpp`)
- `tests/fic/rollback/MutationJournalTests.cpp`,
  `tests/fic/rollback/RollbackExecutorTests.cpp`,
  `tests/fic/modules/net/ssh/SshApplyRollbackTests.cpp`
- `docs/rollback.md`

## Validation

- Full CMake build (build-tests, ubuntu-24.04): exit 0.
- Full CTest: 100% (96/96 passed; 1 pre-existing env-dependent skip:
  `command_hash_batch_tests`).
- Targeted до full run: mutation_journal_tests, rollback_executor_tests,
  ssh_apply_rollback_tests, ssh_runtime_tests, file_handler_options_tests —
  все passed.
- `git diff --check`: passed.

## Remaining

- Residual TOCTOU между re-proof и fsync (и между verify и re-proof) —
  known MVP limitation, не filesystem CAS.
- Native интеграционной проверки с реальным sshd не выполнялось (sandbox);
  только fake-runner unit tests.
- Dynamic journal extension для untracked occurrences не реализован
  (conservative fail closed).
- Retarget активного SSH desired value — fail closed (disable → change →
  enable).
- `build-check/` — старый fic-only build (без тестов); актуальный полный
  build — `build-tests/` (требует libglib2.0-dev для session-agent).
