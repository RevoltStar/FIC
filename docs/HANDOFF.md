# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `8180806` (предыдущий follow-up persistent
  rollback SSH).
- Изменения второго follow-up — в рабочем дереве, не закоммичены.

## Current task

- Follow-up к persistent rollback `NET/SshEdit`: repeated apply без
  незаписанных mutations (fail closed на untracked occurrences), ordered
  mutation-local BEFORE/AFTER classification, identical duplicates, BEFORE
  runtime reconciliation, компенсация по exact FIC-installed state.

## Accepted architecture / invariants

- Undo payload: `UndoRestoreSshDirective{parameter, appliedValue, occurrences}`,
  где `occurrences` — `SshDirectiveOccurrenceMutation{beforeLine, afterLine}`
  (нормализованный keyword; `beforeLine=null` — строка вставлена FIC).
  `occurrenceIndex` удалён (Вариант B): порядок вектора полностью выражает
  identity. Одинаковые `afterLine` валидны. Payload self-contained, без
  full-file snapshot.
- Classification — ordered mutation-local projection: проекция target
  resource (active-директивы keyword + exact recorded BEFORE/AFTER строки,
  в file order) сравнивается целиком с AFTER- и BEFORE-последовательностями.
  Никакого независимого per-occurrence `countExactLines()`. `beforeLine`
  одной occurrence может совпадать с `afterLine` другой без ложного Conflict.
- Repeated apply: если существует active `UndoRestoreSshDirective` ресурса,
  generic `setValue()` не вызывается. Текущие вхождения сопоставляются
  слотам (`matchRecordedMutationForRepair`): owned drifted slot ремонтируется
  до recorded AFTER (baseline сохраняется); untracked occurrence → fail
  closed (файл и journal не изменяются). Single insertion repairable только
  при полном отсутствии keyword.
- BEFORE ≠ сразу `NothingToDo`: сначала runtime reconciliation (`sshd -T`
  + reload активного сервиса), только после успеха `NothingToDo`/`RolledBack`;
  провал — `Failed`, запись активна, disable отказан.
- Компенсация (apply и rollback) — conditional restore по exact
  FIC-installed state: `restoreSshConfigContentIfCurrentState(path, content,
  expectedTargetState)`; expected state — `AtomicWriteResult::
  installedTargetState` (temp-inode/content/metadata, опубликованные rename;
  при post-rename durability ошибке `installed=true`). Свежий snapshot как
  proof of ownership запрещён.
- TOCTOU: optimistic expected-target precondition (`captureTargetState` +
  `saveFileIfUnchanged`/`writeWithResult`). Это НЕ полноценный filesystem
  CAS: между финальной проверкой и `rename()` остаётся малое residual race
  window против non-cooperating writer (известное ограничение).
- Journal serialization: `occurrences` (before/after, порядок = identity);
  legacy форматы (`fingerprint`/`reverse_edits`, промежуточный `4156ac9`)
  отвергаются fail closed. Historical SSH record засчитывается как resolved
  только при статусе `RolledBack`/`Detached`; иные — fail closed.
  Writer→reader invariant покрыт тестом на всех production plan fixtures.
- Legacy (нет journal-записей): директива присутствует в global section →
  `Unsupported`; отсутствует → `NothingToDo`.
- Enrollment `NET/SshEdit` — только explicit whitelist; неизвестная политика
  → `Unsupported`.

## Completed

- `SshConfigFile`: ordered projection classification; repair matcher
  (`matchRecordedMutationForRepair` + `applyRecordedRepairEdits`).
- `Ssh::apply`: journal lookup до любой мутации; ветка repeated apply через
  existing undo; first apply — plan → Prepared → apply; compensation по
  `installedTargetState`; beforeRestoreHook_ test seam.
- `SshRollback`: BEFORE runtime reconciliation; conditional компенсация;
  `beforeRestore` seam; `restoreSshConfigContent` →
  `restoreSshConfigContentIfCurrentState`.
- fic-core: `AtomicWriteResult::installed` + `installedTargetState`
  (captured до rename из temp fd; исправлен баг fstat-после-close);
  `saveFileIfUnchanged` возвращает installed state.
- `MutationJournal`: distinct-afterLine требование убрано; структурные
  проверки сохранены.
- Тесты новые: BEFORE/AFTER collision rollback, identical duplicates +
  restart, repeated apply refuse untracked occurrence, writer→reader
  payload invariant (5 fixtures), apply/rollback compensation race,
  BEFORE crash recovery (reload success/fail).

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
- Residual TOCTOU window между final check и `rename()` — known limitation
  (optimistic precondition, не filesystem CAS).
- Точный textual AFTER/BEFORE matching: любое внешнее изменение
  FIC-controlled строки (включая comment-out) даёт `Conflict` — осознанный
  fail-closed выбор, three-way merge не реализовывался.
- Dynamic journal extension для untracked occurrences не реализован
  (осознанно; conservative fail closed).
