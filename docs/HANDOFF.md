# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `dc76786949bdcf0be88162e1cb0f03b944a597ed`
  (follow-up №5 к persistent rollback SSH).

## Current task

- Follow-up №6 (infrastructure fix, узкий scope): разделение semantics
  fresh-missing vs reload-missing в `MutationJournal::load()` + poison при
  любом failed reload + defensive `usable()`-гейт в
  `DaemonMutationJournal::tryGet()` после lazy recovery.

## Accepted architecture / invariants

- **Journal load lifecycle** (docs/rollback.md — authoritative):
  `fresh + missing → Healthy empty (bootstrap, только
  `loaded_==false && Healthy`)`; `Healthy + successful reload → Healthy`;
  `Healthy/Indeterminate + failed reload → Indeterminate, records_/nextId_/
  loaded_ не трогаются`; `Indeterminate + successful durable reload →
  Healthy`; `Indeterminate (или loaded) + missing file → load()==false,
  «journal disappeared during reload/recovery; provenance cannot be treated
  as empty», fail closed`. Исчезновение ранее известного journal НЕ
  эквивалентно empty journal; автореконструкция из in-memory не выполняется.
- Централизованный `MutationJournal::failLoad(message, error)`: health =
  Indeterminate, records_/nextId_/loaded_ не мутируются; все failure-ветки
  load() идут через него. Fresh + broken journal: load false, loaded=false,
  health=Indeterminate (нельзя потом отbootstrap'иться через удаление
  битого файла).
- **`DaemonMutationJournal::tryGet()` contract**: non-null IFF journal
  существует AND `usable()` после всех recovery-действий — никогда только
  по факту `load()==true`; initial open тоже проверяет `usable()`.
- **`usable() = loaded_ && Healthy`**: operational-решения (apply, rollback,
  disable ownership resolution, journal-backed detach) опираются только на
  usable-журнал; `records()/activeRecords()` — raw inspection API.
- **Generic `AtomicFileWriter::ensureTargetDurableIfCurrentState(path,
  expected, error)`**: targetStateMatches + fsync каталога. Используется:
  journal load, journal persist transparent finish, SSH Prepared
  AFTER/BEFORE recovery, rollback BEFORE recovery. Residual TOCTOU между
  re-prove и fsync — known MVP limitation (не CAS).
- **installed != durable**: `rename` → `installed=true`; parent directory
  fsync → `durabilityConfirmed=true`; test seam
  `setDirectoryFsyncHookForTests` покрывает и barrier fsync.
- Prepared recovery: AFTER → `verifyPolicyValue` → state-bound barrier →
  reload → commit; BEFORE → validate → state-bound barrier → reload →
  discard → fresh apply; drift → fail closed. Файл при recovery не
  перезаписывается.
- `MutationJournal::persist()` — tri-state (NotInstalled / Persisted /
  Indeterminate); порядок: temp write → temp fsync → rename → parent fsync.
  JSON schema (kSchemaVersion=1) не менялась; новые semantics — runtime
  lifecycle only.
- Undo payload / classification / enrollment / legacy invariants — без
  изменений (см. docs/rollback.md).

## Completed

- `MutationJournal::load()`: fresh-vs-reload missing semantics, poison при
  любом failed reload через `failLoad()`.
- `DaemonMutationJournal`: defensive `usable()` re-check в lazy recovery и
  initial open; документирован tryGet contract.
- Тесты новые: healthy reload missing → fail closed; Indeterminate +
  missing (Applied→RolledBack in-memory preserved, mutations refused);
  Healthy→malformed reload poison + mutations refused + recovery after fix;
  daemon tryGet missing after Indeterminate → nullptr; fresh malformed →
  Indeterminate/unloaded; executor: Indeterminate + missing journal →
  rollback Failed (не NothingToDo); fresh missing расширена (Healthy/usable).

## Changed areas

- `fic/src/rollback/` (`MutationJournal.{h,cpp}`,
  `DaemonMutationJournal.{h,cpp}`)
- `tests/fic/rollback/MutationJournalTests.cpp`,
  `tests/fic/rollback/RollbackExecutorTests.cpp`
- `docs/rollback.md` (lifecycle table, missing-vs-reload semantics)

## Validation

- Targeted: mutation_journal_tests (33 PASS), rollback_executor_tests
  (52 PASS) — passed.
- Full CMake build (build-tests, ubuntu-24.04): exit 0.
- Full CTest: 100% (96/96 passed; 1 pre-existing env-dependent skip:
  `command_hash_batch_tests`).
- `git diff --check`: passed.

## Remaining

- Residual TOCTOU между re-proof и fsync — known MVP limitation.
- Если внешний actor портит journal при Healthy in-memory singleton, FIC
  узнаёт об этом только при следующем persist/reopen/restart — принятое
  ограничение модели (не continuous monitoring).
- Native интеграционной проверки с реальным sshd не выполнялось (sandbox).
- `build-check/` — старый fic-only build; актуальный полный build —
  `build-tests/`.
