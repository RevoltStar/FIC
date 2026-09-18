# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `b34ff20` (GRUB hardening session 1 закоммичена).
- Рабочее дерево содержит незакоммиченный второй этап GRUB hardening
  (fixes #1–#4 + regression tests T1–T11, см. Current task).

## Current task

- **GRUB rollback hardening, этап 2** — четыре фикса, все завершены в
  production-коде и тестах, незакоммичено:
  1. **Debian rebuild-input topology validation** —
     `validateGrubRebuildInputs()` (`GrubConfiguration.cpp`) при
     непустом `baseDefaultsPath` дополнительно вызывает
     `validateGrubDropInTopology()` →
     `GrubManagedConfig::validateTopology()`: безопасная цепочка
     каталогов, чужие `*.cfg` — regular non-symlink, ни один не
     сортируется после `zzzz-fic.cfg`; отсутствие самого managed-файла
     легитимно. Поскольку все rebuild-пути (apply, idempotent,
     rollback, reconciliation, компенсация) уже маршрутизируются через
     `validateGrubRebuildInputs()` / `rebuildGrub()`, покрытие полное.
  2. **Retained canonical empty drop-in** — удаление последнего
     FIC-ключа в Debian-топологии больше НЕ unlink'ает
     `zzzz-fic.cfg`: остаётся header-only артефакт
     (`# Managed by FIC. Do not edit.`). Удалены `removeOwnedManagedFile`
     и `regularFileExists` (`GrubRollback.cpp`), compensation-ветка
     `artifactRemoved` (exclusive-create restore) удалена — компенсация
     только точный CAS-restore `installedState`.
  3. **Canonical-strict ALT block grammar** — `parseBlockAssignment`
     (`GrubManagedBlock.cpp`) требует `line == key + "=" +
     encodeGrubManagedValue(decoded)` (canonical re-encode equality):
     отклоняет пробелы вокруг `=`, ведущие/завершающие пробелы,
     инлайн-комментарии. Строки тела блока парсятся через новый
     `physicalLineContent()` (только CR/LF strip, без trim);
     `trimCopy` в файле больше не используется.
  4. **ALT idempotent-apply snapshot re-proof** — idempotent ветка
     `GrubConfiguration::ensureManagedValue()` перед rebuild доказывает
     `AtomicFileWriter::targetStateMatches(loadedState_)`; stale snapshot
     → fail closed, rebuild не запускается, внешние байты сохраняются.
     Debian-эквивалент (`snapshotUnchanged()` в managed idempotent
     path) подтверждён существующим.
- Test seams: новый `setGrubPostLoadMutationHookForTests()` /
  `fireGrubPostLoadMutationHookForTests(path)` (self-clearing, вызывается
  в idempotent re-proof перед `targetStateMatches`).

## Accepted architecture / invariants

- Ownership-release: rollback никогда не восстанавливает pre-FIC значение
  и не хранит snapshots; журнал доказывает только (key, appliedValue).
- Обязательная пересборка grub.cfg при каждом rollback, включая
  NothingToDo (crash-after-source-rollback инвариант); всегда на
  провалидированных входах.
- Авторитетное описание инвариантов (validated rebuild inputs, typed
  probe, single-snapshot CAS, reconciliation re-proof, EOF-сепаратор):
  `docs/rollback.md`, раздел «GRUB rollback (OSS/Grub)».
- Новые GRUB-политики никогда не становятся rollback-Supported
  автоматически — только через явное расширение whitelist в
  `RollbackExecutor.cpp` + journal integration.

## Completed

- Fixes #1–#4 в `fic/src/modules/oss/grub/{GrubConfiguration.h/cpp,
  GrubManagedBlock.cpp, GrubRollback.cpp}` (детали в Current task).
- Тесты:
  - `GrubRollbackJournalTests.cpp`: тест Debian last-key rollback
    переписан под retention header-only drop-in; добавлен
    `testAltIdempotentApplyStaleSnapshot` (post-load mutation hook,
    external bytes byte-exact, запись остаётся активной).
  - `GrubPolicyTests.cpp`: 4 новых malformed-кейса грамматики
    (whitespace around `=`, leading/trailing ws, inline comment);
    canonical render→parse→render round-trip с escapes; 3
    topology-кейса в `testBaseDefaultsValidation` (поздний чужой
    drop-in, symlink чужой drop-in — fail closed; отсутствие managed —
    apply ок); `testAltIdempotentReproofRace`.
- `docs/rollback.md`: topology validation, canonical empty drop-in
  (retention + rationale), canonical-strict грамматика; rollback-семантика
  last-key удаления обновлена.

## Changed areas

- `fic/src/modules/oss/grub/`, `docs/rollback.md`, `docs/HANDOFF.md`,
  `tests/fic/modules/oss/grub/{GrubPolicyTests.cpp,
  GrubRollbackJournalTests.cpp}`.

## Validation

- Targeted build + CTest: `grub_policy_tests`,
  `grub_rollback_journal_tests` — PASS (после всех правок).
- Full build `fic` target — OK.
- `git diff --check`: clean.
- Полный build всех targets и полный CTest для этапа 2 — см. Remaining.

## Remaining

- Запустить full build (`cmake --build build-check -j2`) и полный CTest;
  затем коммит второго этапа hardening.
- Sanitizer build не выполнялся (профиль в проекте отсутствует) — не
  заявлять как выполненный.
