# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `4156ac9` (SSH rollback MVP закоммичен).
- Изменения follow-up (mutation-local drift, TOCTOU, компенсация) — в
  рабочем дереве, не закоммичены.

## Current task

- Follow-up к persistent rollback `NET/SshEdit`: замена whole-global
  fingerprint на mutation-local BEFORE/AFTER matching, idempotent
  crash-recovery, optimistic conditional writes shared `sshd_config`,
  prepared-discard только при полной подтверждённой компенсации.

## Accepted architecture / invariants

- Undo payload: `UndoRestoreSshDirective{parameter, appliedValue, occurrences}`,
  где `occurrences` — `SshDirectiveOccurrenceMutation{occurrenceIndex,
  beforeLine, afterLine}` (нормализованный keyword; `beforeLine=null` —
  строка вставлена FIC). Payload self-contained, без full-file snapshot.
- Rollback: classifyRecordedMutation — для каждой occurrence точное
  текстовое совпадение текущей строки global section с afterLine (AFTER) или
  beforeLine (BEFORE), однозначно (count==1). Все AFTER → undo; все BEFORE →
  `NothingToDo` → journal `RolledBack`; иначе (смешанное/неоднозначное/
  drift, в т.ч. вставленная директива с другим значением) → `Conflict`.
  Абсолютные line index'ы не идентификатор мутации; вставленная директива
  при BEFORE-проверке требует полного отсутствия keyword в global section.
  Match/includes не восстанавливаются и не мешают. Регистр не нормализуется
  (fail closed).
- Legacy historical SSH record засчитывается как resolved только при статусе
  `RolledBack`/`Detached`; иные статусы — fail closed.
- TOCTOU: `AtomicFileWriter::captureTargetState` (shared helper в fic-core) +
  `FileHandler::saveFileIfUnchanged` (conditional write через
  `expectedTargetState`). `SshConfigFileHandler::loadConfig()` строится из
  одного snapshot; apply и rollback пишут только при неизменности файла;
  concurrent modification → отказ без перезаписи (Conflict для rollback,
  apply failure с discard нового Prepared для apply).
- Prepared discard: новый Prepared удаляется только если доказано, что
  системная мутация не произошла (write refused, `AtomicWriteResult::
  installed=false`) либо apply-time компенсация полностью подтверждена
  (restore + `sshd -T` + reload restored при активном сервисе); иначе
  остаётся активным.
- Journal serialization: `occurrences` (occurrence/before/after); legacy
  формат (`fingerprint`/`reverse_edits`) явно отвергается при загрузке —
  записи промежуточного коммита 4156ac9 требуют ручного разрешения (feature
  не release'd, backward compat не требуется).
- Legacy (нет journal-записей): директива присутствует в global section →
  `Unsupported`; отсутствует → `NothingToDo`.
- Enrollment `NET/SshEdit` — только explicit whitelist; неизвестная политика
  → `Unsupported`.

## Completed

- `SshLineReverseEdit` + fingerprint → `SshDirectiveOccurrenceMutation`;
  `planSetValue`/`setValue` переписаны; `classifyRecordedMutation` +
  `applyRecordedReverseEdits` вместо `applyReverseEdits`/fingerprint.
- `SshRollback`: BEFORE→NothingToDo (`SshRollbackResult::nothingToDo`),
  conditional write, transactional restore поверх conditional write.
- `Ssh::apply`: single snapshot, conditional save, §11 fix (Prepared
  остаётся при неполной компенсации), beforeWriteHook_ test seam.
- `RollbackExecutor`: NothingToDo маппинг, §21 явная проверка статусов.
- `MutationJournal`: сериализация `occurrences` + fail-closed reject legacy
  payload; усиленная валидация (occurrence indices с 0, before!=after,
  distinct after lines, insert = единственная occurrence).
- fic-core: `AtomicFileWriter::captureTargetState`,
  `AtomicWriteResult::preconditionFailed`, `FileHandler::saveFileIfUnchanged`
  (+`loadSnapshot()`).
- Тесты: мульти-политики (2 и 4 политики, произвольный порядок, insert+
  replace, дубликаты), crash-after-undo → NothingToDo, TOCTOU apply и
  rollback (deterministic beforeWrite seam), неполная компенсация (validation/
  reload restored fails → Prepared остаётся; полная → Prepared discarded),
  legacy journal reject, malformed occurrences payload.

## Changed areas

- `fic-common/fic-core/` (`AtomicFileWriter.{h,cpp}`, `FileHandler.{h,cpp}`)
- `fic/src/rollback/` (`MutationRecord.h`, `MutationJournal.cpp`,
  `RollbackExecutor.cpp`)
- `fic/src/modules/net/ssh/` (`Ssh.{h,cpp}`, `SshConfigFile.{h,cpp}`,
  `SshRollback.{h,cpp}`)
- `tests/fic/rollback/`, `tests/fic/modules/net/ssh/SshApplyRollbackTests.cpp`
- `docs/rollback.md`

## Validation

- Full CMake build (build-check, ubuntu-24.04): 100%, exit 0.
- Full CTest: 96/96 passed (1 pre-existing env-dependent skip:
  `command_hash_batch_tests`).
- `git diff --check`: passed.

## Remaining

- Изменения не закоммичены.
- Native интеграционной проверки с реальным sshd не выполнялось (sandbox);
  только fake-runner unit tests.
- Точный textual AFTER/BEFORE matching: любое внешнее изменение
  FIC-controlled строки (включая comment-out) даёт `Conflict` — осознанный
  fail-closed выбор, three-way merge не реализовывался.
