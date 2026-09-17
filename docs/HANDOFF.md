# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `7544a0baaad6ae89787dd579c56a7301efe1c061`
  (follow-up №7 к persistent rollback SSH).

## Current task

- Follow-up №8 (infrastructure fix, узкий scope): эксклюзивный virgin
  bootstrap journal (no-replace), strict `loadExisting()`, final journal
  proof после witness creation, отдельное lifecycle-состояние.

## Accepted architecture / invariants

- **Journal load lifecycle** (docs/rollback.md — authoritative):
  `Healthy + successful reload → Healthy`; failed reload → Indeterminate,
  records_/nextId_/loaded_ не трогаются; исчезновение ранее известного
  journal НЕ эквивалентно empty journal; автореконструкция из in-memory не
  выполняется.
- **Virgin bootstrap — только no-replace**: пустой journal создаётся
  `AtomicFileWriter` `exclusiveCreate` (`renameat2(RENAME_NOREPLACE)` /
  non-replacing fallback). Exclusive-create conflict классифицируется
  повторным probe пути (не errno-текст): если J появился — bootstrap
  возвращает `ConflictJournalExists` и `initializeFresh` переоценивает
  persistent state table (bounded, 3 попытки, далее fail closed). Чужой
  journal NEVER не считается «нашим пустым» — загружается через обычные
  строгие правила. Bootstrap code NEVER replaces an existing journal.
- **`loadExisting()` / `loadImpl(MissingJournalPolicy)`**: одна реализация
  parser/durability; `load()` = raw primitive (`AllowFreshEmpty`, только
  тесты/diagnostics/legacy fixtures), `loadExisting()` = strict
  (`RequireExisting`: missing J — всегда ошибка). Весь witness-aware flow
  использует только `loadExisting`.
- **Final proof**: migration (J exists + W missing) = loadExisting J →
  createWitness → ПОВТОРНЫЙ loadExisting J; virgin bootstrap = exclusive J →
  witness → loadExisting J. Lifecycle публикуется только после proof обоих
  объектов. Это НЕ filesystem transaction: известный residual re-proof→fsync
  TOCTOU остаётся.
- **`lifecycleInitialized_`** (доступен `lifecycleInitialized()`): true
  только после полного witness-aware flow на данном объекте; distinct от
  `loaded_`. Ошибка witness creation/malformed witness НЕ выставляет его;
  retry `initializeOrLoad()` на том же объекте заново проходит state table
  (raw reload witness обойти не может). После успешной lifecycle повторный
  `initializeOrLoad()` = строгий live-reload (`loadExisting`), т.е. missing J
  после инициализации — всегда fail closed (follow-up №6 semantics). Сырой
  `load()` lifecycle не завершает и operational-объект не делает.
- **`DaemonMutationJournal`**: публикует journal только после
  `initializeOrLoad() && usable() && lifecycleInitialized()`.
- **Persistent initialization witness** (`journalPath + ".initialized"`,
  versioned JSON, exclusive create 0600, strict validation) — без изменений
  относительно follow-up №7; witness-race (чужой валидный durable witness →
  успех) сохранён и отличается от journal-race (никогда не принимать чужой
  journal как свой).
- **State table** (`J/W` presence + validity, provenance loss при
  `J missing + W valid` — fail closed навсегда, restart — НЕ recovery) —
  без изменений (docs/rollback.md).
- **Известные ограничения**: удаление внешним actor'ом обоих файлов
  неотличимо от virgin install; journal+witness — одна logical retention
  pair, purge-логики пары нет (TODO в docs); нет cross-process
  serializability (исправлен только bootstrap-destroy race).

## Completed

- `MutationJournal`: exclusive virgin bootstrap + bounded state-table retry;
  `loadImpl`/`loadExisting`; final proof в bootstrap и migration;
  `lifecycleInitialized_` + `initializeExistingJournal`; тестовые seams
  `setBeforeVirginJournalInstallHookForTests` /
  `setBeforeFinalJournalProofHookForTests` (copy-before-invoke — hook может
  переустанавливать slot во время исполнения).
- `DaemonMutationJournal`: gating на `lifecycleInitialized()`.
- Тесты новые (8): concurrent full bootstrap (records сохранены, A
  присоединяется), concurrent J-only → migration без rewrite, J исчезает
  после witness (bootstrap и migration) + provenance loss на restart,
  same-object retry после witness failure, same-object malformed witness не
  обходится, deletion после успешной lifecycle → fail closed, migration не
  переписывает файл (inode+content).
- docs/rollback.md: concurrency-кейс, loaded vs lifecycle initialized,
  обновлённая state table; header-комментарии без «restart as recovery».

## Changed areas

- `fic/src/rollback/` (`MutationJournal.{h,cpp}`,
  `DaemonMutationJournal.cpp`)
- `tests/fic/rollback/MutationJournalTests.cpp` (53 PASS)
- `docs/rollback.md`, `docs/HANDOFF.md`

## Validation

- mutation_journal_tests 53 PASS; rollback_executor_tests 53 PASS;
  ssh_apply_rollback_tests + targeted journal/ssh/apply — passed.
- Full build (build-tests): exit 0. Full CTest: 96/96 (1 pre-existing skip
  `command_hash_batch_tests`).
- `git diff --check`: passed.

## Remaining

- Residual TOCTOU между re-proof и fsync — known MVP limitation.
- Удаление обоих файлов внешним actor'ом — принятое ограничение модели.
- `build-check/` — старый fic-only build; актуальный полный build —
  `build-tests/`.