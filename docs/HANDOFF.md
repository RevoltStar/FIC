# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `ff48a9c22a829307ec9eecafe326c26a7946b03f`
  (follow-up №6 к persistent rollback SSH).

## Current task

- Follow-up №7 (infrastructure fix, узкий scope): persistent initialization
  witness (`<journal path>.initialized`) для различения «virgin bootstrap» vs
  «journal существовал, но исчез» через рестарт daemon;
  `J missing + W valid` → fail closed навсегда, включая после restart.

## Accepted architecture / invariants

- **Journal load lifecycle** (docs/rollback.md — authoritative):
  `Healthy + successful reload → Healthy`; failed reload → Indeterminate,
  records_/nextId_/loaded_ не трогаются; исчезновение ранее известного
  journal НЕ эквивалентно empty journal; автореконструкция из in-memory не
  выполняется.
- **Persistent initialization witness** (`MutationJournal::initializeOrLoad`
  — единственный operational entrypoint; сырой `load()` — primitive для
  тестов/live-reload). Witness path детерминированно выводится:
  `journalPath + ".initialized"` (по умолчанию
  `/opt/fic/db/mutation-journal.json.initialized`); `setOverridePath`
  автоматически выводит witness path. Формат: versioned JSON
  `{"schema_version": 1, "initialized": true}` (`kWitnessSchemaVersion=1`,
  независимая версия, journal JSON schema kSchemaVersion=1 не менялась).
  Свойства: crash-safe create (temp fsync → rename → parent fsync,
  `AtomicFileWriter` exclusiveCreate, mode 0600); strict validation
  (regular file only, symlinks/non-regular refused, точное содержимое,
  state-bound durability barrier); никогда не удаляется/не перезаписывается
  FIC, включая empty records; malformed/unreadable witness → fail closed,
  без auto-repair.
- **State table** (fresh object, `initializeFresh`):
  `J missing + W missing` → virgin bootstrap (durable empty journal →
  durable witness → load/prove; journal-before-witness порядок);
  `J exists + W missing` → migration (proven load → durable witness, journal
  не перезаписывается); `J exists + W valid` → normal; `J exists + W
  invalid` и `J missing + W invalid` → fail closed (anomaly);
  `J missing + W valid` → **provenance loss, fail closed навсегда**,
  ошибка «provenance may have been lost; manual provenance recovery is
  required» (restart — НЕ recovery). Live-объект (`loaded_`) при
  `initializeOrLoad` делегирует `load()` — follow-up №6 semantics
  сохранены.
- Witness `installed != durable`: rename-ok + fsync-fail → transparent
  durability finish или fail closed (следующий startup — migration path).
- **`DaemonMutationJournal::tryGet()` contract**: non-null IFF `usable()`
  после всех recovery-действий; lazy recovery использует
  `initializeOrLoad`; ошибка — «successful durable reload/recovery of
  persistent journal state is required» (упоминание restart как recovery
  убрано).
- **Известные ограничения** (задокументированы в docs/rollback.md):
  удаление внешним actor'ом обоих файлов неотличимо от virgin install (нет
  stronger trust anchor в MVP); journal+witness — одна logical retention
  pair, purge-логики пары пока нет (TODO в docs).
- Централизованный `failLoad()`, `usable() = loaded_ && Healthy`,
  `ensureTargetDurableIfCurrentState`, tri-state persist, Prepared recovery,
  undo payload / classification / enrollment — без изменений относительно
  follow-up №6 (см. docs/rollback.md).

## Completed

- `MutationJournal`: `witnessPath()`, `witnessIsValid()`, `createWitness()`,
  `initializeOrLoad()` + `initializeFresh()`/`bootstrapVirgin()`;
  `kWitnessSchemaVersion`.
- `DaemonMutationJournal`: initial open и lazy recovery переведены на
  `initializeOrLoad`; сообщения об ошибках обновлены.
- Тесты новые (12): fresh bootstrap (оба файла durable, witness document),
  restart после bootstrap (records reload), journal deletion + restart →
  tryGet nullptr (P1), apply regression после provenance loss, interrupted
  bootstrap → recover, migration pre-witness (records сохранены), witness
  creation fsync failure → fail closed + retry, rename-ok+fsync-fail →
  transparent finish, тот же permanent → fail closed + retry, malformed
  witness, zero-byte witness, symlink witness, empty records → witness
  остаётся; executor: provenance loss после restart → rollback Failed +
  новый baseline невозможен.
- docs/rollback.md: witness-секция, state table, ограничения, restart-
  формулировка; устаревший комментарий executor-теста обновлён.

## Changed areas

- `fic/src/rollback/` (`MutationJournal.{h,cpp}`,
  `DaemonMutationJournal.{h,cpp}`)
- `tests/fic/rollback/MutationJournalTests.cpp` (45 PASS),
  `tests/fic/rollback/RollbackExecutorTests.cpp` (53 PASS)
- `docs/rollback.md`, `docs/HANDOFF.md`

## Validation

- Targeted: mutation_journal_tests (45 PASS), rollback_executor_tests
  (53 PASS) — passed.
- Full CMake build (build-tests, ubuntu-24.04): exit 0.
- Full CTest: 100% (96/96 passed; 1 pre-existing env-dependent skip:
  `command_hash_batch_tests`).
- `git diff --check`: passed.

## Remaining

- Residual TOCTOU между re-proof и fsync — known MVP limitation.
- Удаление обоих файлов внешним actor'ом — принятое ограничение модели.
- Native интеграционной проверки с реальным sshd не выполнялось (sandbox).
- `build-check/` — старый fic-only build; актуальный полный build —
  `build-tests/`.