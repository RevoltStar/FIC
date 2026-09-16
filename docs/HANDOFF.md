# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `9a42417595483ffe8c691eae87405b1a0062c5d4`
  (follow-up №2 к persistent rollback SSH).
- Изменения третьего follow-up — в рабочем дереве, не закоммичены.

## Current task

- Follow-up №3 к persistent rollback `NET/SshEdit`: Prepared recovery до
  compliance fast-path, active value change fail closed, plan identity
  preflight (planner → classifier), прокидывание `installed=true` через
  `FileHandler` и post-install failure handling в SSH apply/rollback.

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
- `Ssh::apply()`: journal lookup ДО compliance; порядок: значение → load →
  journal → Prepared recovery → RollbackFailed fail closed → active
  value-change refusal → compliance → repeated-apply/fresh. `Prepared`
  state machine: AFTER → validate/reload/commit Applied; BEFORE →
  validate/reload/discard/fresh apply; drift → conflict fail closed. Файл
  при recovery не перезаписывается.
- Active value change (`expectedValue != undo.appliedValue`) при активной
  SSH-мутации — явный отказ (файл/journal не изменяются, baseline
  сохраняется); retarget — будущая transactional-версия.
- Plan identity preflight: `SshConfigFileHandler::
  validatePlannedRollbackIdentity(plan)` симулирует план на in-memory копии
  и требует `classify == After` тем же production-алгоритмом (общий статик
  `classifyLinesAgainstMutation`); отказ ДО journal и ДО записи файла
  (foreign-comment collision fail closed). Валидные duplicate-сценарии
  сохранены.
- Atomic write: `FileHandler::saveFileIfUnchanged()` возвращает
  `FileSaveOutcome{result, installed, preconditionFailed,
  installedTargetState}`; `installed=true` при `result=Failed` означает
  состоявшуюся замену (post-rename durability failure) — SSH apply
  компенсирует по `installedTargetState` (успех → discard new Prepared /
  существующий baseline остаётся; недоказано → запись активна), SSH
  rollback при installed reverse-write продолжает validate/reload и не
  маркирует Success без полного подтверждения. Test-only seam:
  `AtomicFileWriter::setDirectoryFsyncHookForTests` (по target path).
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

- `Ssh::apply`: перестроен порядок (provenance до compliance); Prepared
  recovery state machine; RollbackFailed fail closed; active value-change
  refusal; plan identity preflight перед `recordPreparedMutation`;
  post-install failure компенсация.
- `SshConfigFile`: классификация вынесена в общий
  `classifyLinesAgainstMutation` (member classify + preflight используют
  один алгоритм); `validatePlannedRollbackIdentity`; `buildTargetProjection`
  → статический `buildProjectionForLines`.
- `SshRollback`: structured `FileSaveOutcome`; installed reverse-write
  продолжает validate/reload; fail closed при неизвестном installed state;
  `restoreSshConfigContentIfCurrentState` считает installed=true успехом
  restore (замена опубликована, провалилась только durability).
- fic-core: `FileHandler::FileSaveOutcome` (замена
  `saveFileIfUnchanged(error, installedState)` — контракт заменён чисто);
  `AtomicFileWriter::setDirectoryFsyncHookForTests` (test-only seam для
  post-rename durability failure).
- Тесты новые: Prepared AFTER recovery (success/reload fail/commit fail +
  retry), Prepared BEFORE recovery (fresh apply + reload fail), Prepared
  Conflict fail closed, Prepared + changed desired value, active value
  change refusal (+disable rollback), foreign-comment collision refusal,
  apply/rollback post-install durability failure, fic-core
  dir-fsync-failure + FileHandler propagation, planner→classifier invariant
  на всех fixtures.

## Changed areas

- `fic-common/fic-core/` (`AtomicFileWriter.{h,cpp}`, `FileHandler.{h,cpp}`)
- `fic/src/rollback/` (`MutationRecord.h`, `MutationJournal.cpp`,
  `RollbackExecutor.cpp`)
- `fic/src/modules/net/ssh/` (`Ssh.{h,cpp}`, `SshConfigFile.{h,cpp}`,
  `SshRollback.{h,cpp}`)
- `tests/fic/rollback/`, `tests/fic/modules/net/ssh/SshApplyRollbackTests.cpp`,
  `tests/common/core/fs/FileHandlerOptionsTests.cpp`
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
- Retarget активного SSH desired value (multi-generation journal
  transaction) — TODO, сейчас fail closed (disable → change → enable).
- Foreign-comment collision: если существующая чужая строка точно совпадает
  с планируемой FIC-generated (`#Port 22`), first apply отказывается
  (fail closed) — foreign-комментарии не присваиваются.
