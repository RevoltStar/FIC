# Rollback выполненных мутаций (MVP)

Этот документ — авторитетное описание persistent rollback-инфраструктуры FIC.
Один раз описанная семантика в других файлах дублироваться не должна.

## Принцип

Rollback строится не из описания политики, а из **фактически выполненных**
изменений ОС:

```text
Policy → backend → MutationRecord → persistent MutationJournal
       → policy disable → RollbackExecutor → typed UndoAction
```

Инварианты:

* `Policy` не реализует rollback и не содержит стратегии отката.
* Journal — единственный источник provenance: FIC автоматически отменяет
  только то, что записал в journal как свою мутацию.
* Ownership для SYSCTL определяется **содержимым FIC managed-артефакта**
  (`/etc/sysctl.d/zzzz-fic.conf`), а не текущим effective source. Если
  внешний файл перекрывает FIC-запись, disable всё равно обязан удалить
  FIC-запись из managed-файла, иначе она может снова стать effective после
  исчезновения перекрытия. Effective resolution используется только после
  удаления, чтобы определить оставшееся persistent значение для runtime.
* Системное состояние, которое уже соответствовало политике до `apply`
  (`current == desired`), мутацией не считается и при disable не изменяется.
* Drift FIC-owned значения внутри managed-артефакта — fail closed
  (`Conflict`), молчаливая потеря данных и three-way merge не выполняются.
* Rollback выполняется до смены статуса политики. Частичный откат оставляет
  политику ENABLE и отражается в journal.
* Commit provenance (`Prepared → Applied`) после фактического системного
  изменения не может маскироваться как успех: если persist не удался, apply
  завершается ошибкой, а `Prepared`-запись остаётся активной на диске и
  безопасно разрешается rollback executor'ом.

## Расположение

* `fic/src/rollback/MutationRecord.h` — `MutationRecord`, `MutationStatus`,
  `MutationBackend`, типизированные `UndoAction`.
* `fic/src/rollback/MutationJournal.{h,cpp}` — persistent JSON journal
  (atomic write через `AtomicFileWriter`, fail-closed загрузка).
* `fic/src/rollback/DaemonMutationJournal.{h,cpp}` — singleton демона над
  journal'ом (путь из `FicRuntimePaths::mutationJournalFile`; override
  существует только для тестов).
* `fic/src/rollback/RollbackExecutor.{h,cpp}` — `rollbackPolicyBeforeDisable`,
  enrollment матрица, production deps wiring.
* `fic/src/modules/net/ssh/SshRollback.{h,cpp}` — SSH undo: применение reverse
  delta главного `sshd_config`, валидация `sshd -T`, reload сервиса,
  transactional restore.
* `fic/src/modules/dac/mode_and_owner/DacBaselineRollback.{h,cpp}` — DAC
  platform-baseline undo: переход управляемых объектов к baseline-метаданным
  platform profile (см. «Platform-baseline rollback»).
* `tests/fic/rollback/` — тесты journal и executor.

## Жизненный цикл мутации

```text
Prepared  — journal-запись создана ДО системного изменения
Applied   — backend подтвердил успешную мутацию и postcondition
RolledBack      — undo выполнен (или менять было нечего)
RollbackFailed  — undo не прошёл; запись остаётся активной
Detached        — FIC больше не владеет изменением (не откатывается никогда)
```

Crash-consistency: запись создаётся в состоянии `Prepared` перед системным
изменением и переводится в `Applied` только после подтверждения backend'ом.
Крэш между изменением и коммитом оставляет `Prepared`-запись, поэтому FIC не
теряет provenance. Remaining crash-window между атомарной записью journal и
самим изменением разрешается консервативно: лишняя `Prepared`/`Applied`
запись при disable приводит к проверке фактического состояния
(nothing-to-do / conflict), а не к слепому откату.

Существующие apply-time восстановительные механизмы backend'ов
(restore исходного содержимого при провале postcondition) сохранены;
persistent-запись коммитится только после успешного apply.

### Prepared recovery (SSH backend)

`Ssh::apply()` разрешает provenance (journal lookup) ДО проверки effective
compliance: compliance fast-path никогда не обходит `Prepared`-запись,
иначе крэш между записью файла и reload дал бы ложный успешный apply без
runtime-перезагрузки. Для активной `Prepared`-записи выполняется recovery
state machine (текущий файл классифицируется production-моделью
`classifyRecordedMutation`, файл при recovery никогда не перезаписывается):

```text
Prepared + AFTER
→ verifyPolicyValue(recorded parameter, recorded appliedValue)
  (та же policy postcondition, что и у original apply: effective value,
   scalar match, Match/Include conditional overrides, audit overrides;
   используется recorded appliedValue — recovery сначала завершает старую
   persisted-транзакцию, а не новый desired value)
→ durability barrier (ensureTargetDurableIfCurrentState: re-prove exact
   classified snapshot, затем fsync каталога)
→ reload (если сервис активен)
→ commit Prepared → Applied
Prepared + BEFORE
→ sshd -T validate
→ durability barrier (ensureTargetDurableIfCurrentState: re-prove exact
   classified snapshot, затем fsync каталога)
→ reload (если сервис активен)
→ discard устаревшей Prepared
→ продолжение обычного fresh apply нового desired value
Prepared + ни AFTER, ни BEFORE (drift)
→ conflict, fail closed; apply false, файл не изменён, Prepared остаётся
```

Recovery не имеет права коммитить mutation с более слабой postcondition, чем
original apply: `validateConfiguration()` доказывает только, что sshd может
разобрать effective config, поэтому для AFTER обязательна
`runtime.verifyPolicyValue()` (effective value, Port semantics, scalar match,
условные Match overrides, audit overrides). Любая неудача
verify/validate/barrier/reload/commit/discard оставляет `Prepared` активной и
завершает apply ошибкой (generic repair не выполняется). После recovery
`Applied`-записи проверка active value change применяется как к обычной
активной мутации.

### Active value changes (SSH, MVP)

Изменение желаемого значения при активной SSH-мутации выполняется внутри
apply по ownership-release семантике: предыдущее owned состояние откатывается
(снимаются только существующие доказанные wrapper'ы, удаляется существующий
owned managed block), journal-запись помечается `RolledBack`, файл
перечитывается, и новое значение применяется к фактическому текущему
состоянию конфига. Исчезнувшие извне артефакты предыдущей мутации (вплоть
до `NothingToDo` полного отката) не блокируют смену значения и не
реконструируются. `Conflict` предыдущего отката (неизвестный или
дублирующийся wrapper, ручная правка блока, malformed маркеры) отказывает
apply fail-closed: файл и journal не изменяются.

### Plan identity preflight (planner → classifier)

Первый apply SSH-политики выполняется только если план, просимулированный на
in-memory копии текущего конфига (`validatePlannedRollbackIdentity`),
классифицируется тем же production-алгоритмом rollback-классификатора как
`After`. Иначе (например, чужая существующая строка `#Port 22` коллидирует с
планируемым FIC-комментарием) apply отказывается ДО записи journal и ДО
системной записи: FIC не создаёт мутацию, которую сам не может однозначно
классифицировать. Валидные сценарии дубликатов (`Port 22/Port 2022`, три
одинаковых `Port 22`, before/after collision) сохраняются.

### Atomic write result: installed != durable

`AtomicWriteResult` различает **installed** и **durability-confirmed**:

```text
rename(temp, target) succeeded → installed = true
parent directory fsync succeeded → durabilityConfirmed = true
```

`installed=true` означает только, что target уже несёт новый контент в
работающей системе; до успешного `fsync(parent directory)` rename может быть
потерян при crash/power-loss. Поэтому главный инвариант:

> Journal status нельзя переводить в resolved state (`Applied`, `RolledBack`,
> discard provenance), если persistent system state, на котором основано это
> решение, не имеет подтверждённой durability.

`AtomicFileWriter::writeWithResult()`: pre-install failure →
`installed=false, durabilityConfirmed=false` (persistent state точно не
изменён); rename + провал fsync каталога (в т.ч. test seam) →
`installed=true, durabilityConfirmed=false, installedTargetState` сохранён;
успешный fsync → `durabilityConfirmed=true` (ошибка `close(dirFd)` после
успешного fsync durability не отменяет).

`AtomicFileWriter::ensureTargetDurable(path, error)` — recovery-барьер для
уже наблюдаемого состояния (AFTER/BEFORE проекция, journal-документ,
reverse-запись): открывает parent directory target, выполняет `fsync`, сам
файл не изменяет (temp-файл всегда fsync'ится до rename, поэтому
единственный потерянный barrier — directory entry).

`AtomicFileWriter::ensureTargetDurableIfCurrentState(path, expected, error)`
— state-bound вариант того же барьера: сначала re-prove, что target всё ещё
точно равен captured state (`targetStateMatches`), и только потом fsync
каталога. Ошибки дифференцированы: mismatch → «state changed before
durability confirmation», провал fsync → собственная ошибка fsync. Все
callers, ранее захватившие snapshot (classified sshd_config snapshot,
прочитанный journal-документ, FIC-installed state), обязаны использовать
этот helper вместо голого `ensureTargetDurable()`. Residual TOCTOU между
re-prove и fsync остаётся известным MVP-ограничением (не filesystem CAS).

`FileHandler::FileSaveOutcome` содержит `durabilityConfirmed`;
`FileSaveResult::Installed` возвращается только для
durable-записи. `restoreSshConfigContentIfCurrentState()` возвращает
структурированный `SshRestoreOutcome{installed, durable, preconditionFailed,
installedState}` и не приравнивает `installed=true` к полному успеху;
`ensureSshConfigDurableIfCurrentState()` завершает durability
non-durable restore: сначала re-prove, что target всё ещё точно равен
FIC-installed state (`targetStateMatches` — внешний replacement никогда не
легитимизируется fsync'ом), затем fsync каталога. Компенсация считается
полностью доказанной только при installed + durable + validate +
runtime reconciliation; иначе provenance-запись остаётся активной (fail
closed). Rollback BEFORE-recovery и reverse-запись отката также требуют
durability-барьер до `NothingToDo`/`Success`.

Для deterministic-тестов в `AtomicFileWriter` есть test-only seam
`setDirectoryFsyncHookForTests` (заменяет post-rename fsync каталога И
fsync внутри `ensureTargetDurable` для данного target-path; при simulated
отказе `installed=true, durabilityConfirmed=false`; production-код его не
устанавливает).

`RollbackFailed` при повторном apply SSH fail closed (файл и journal не
изменяются) — фактическое состояние не доказано, статус не «чинится» молча.

## Формат journal

### Journal persistence и durability

`MutationJournal::persist()` использует детализированный
`AtomicFileWriter::writeWithResult()` и различает три исхода:

* **Not installed** (новый документ не опубликован rename'ом): persistent
  journal точно держит предыдущий документ, in-memory состояние безопасно
  откатывается к pre-operation состоянию (strong in-memory consistency
  действует только здесь), операции можно повторять;
* **Installed + durable**: persist успешен;
* **Installed + non-durable** (rename произошёл, fsync каталога не удался):
  persistent state indeterminate относительно будущего crash, но текущий
  target уже содержит новый документ. persist() сначала пытается
  **прозрачно завершить durability**: re-prove
  (`targetStateMatches(installedTargetState)`) + `ensureTargetDurable`;
  успех → persist успешен. Если durability подтвердить нельзя (target
  изменился, fsync снова failed) — журнал переходит в fail-closed состояние
  `JournalHealth::Indeterminate`: in-memory состояние остаётся идентичным
  установленному документу (никогда не откатывается к previous), все
  мутирующие операции (`prepareMutation`, `setStatus`,
  `setStatusWithMessage`, `discard`) отказываются, продолжать нормальную
  работу с неизвестным persistent state запрещено.

**Journal load и `Healthy`**. Readable/parsible journal ≠ `Healthy`.
`Healthy` — свойство durability, и `load()` требует:

```text
capture exact document (AtomicFileWriter::captureTargetState)
→ parse + validate именно snapshot.content
→ re-proof: targetStateMatches(path, snapshot) — тот же документ всё ещё
   занимает путь
→ durability barrier: fsync parent directory
→ только после этого: publish parsed state в памяти, health = Healthy
```

Провал любого шага (включая capture, parse, validate) → `load() == false`,
journal переводится в `Indeterminate` (unusable), in-memory состояние
(`records_`/`nextId_`/`loaded_`) не изменяется и остаётся доступным для
диагностики. Retry `load()` после восстановления fsync или исправления
дискового документа возвращает `Healthy` с записями, соответствующими
дисковому документу.

**Missing journal: bootstrap vs reload**. Отсутствующий файл — валидный
empty journal ТОЛЬКО при initial bootstrap ещё никогда не загружавшегося
объекта (`loaded_ == false` и `Healthy`) БЕЗ initialization witness (см.
ниже): `records = empty`, `nextId = 1`, `loaded = true`, `Healthy`,
directory durability отсутствующего файла не требуется. Исчезновение ранее
известного journal (объект уже был `loaded_` или уже `Indeterminate`) НЕ
эквивалентно empty journal: такой reload завершается ошибкой «mutation
journal disappeared during reload/recovery; provenance cannot be treated as
empty», объект остаётся `Indeterminate`, старые in-memory записи
сохраняются. Автоматическое восстановление удалённого journal из in-memory
состояния не выполняется (fail closed). Жизненный цикл:

```text
fresh + missing (без witness)  → Healthy empty journal (bootstrap)
Healthy + successful reload    → Healthy новый snapshot
Healthy + failed reload        → Indeterminate, старая память сохранена
Indeterminate + successful
  durable reload               → Healthy
Indeterminate + missing journal→ Indeterminate, fail closed
```

**Persistent initialization witness**. Рядом с journal существует
companion-файл `<journal path>.initialized` (по умолчанию
`/opt/fic/db/mutation-journal.json.initialized`) — persistent witness того,
что journal lifecycle был инициализирован на данной установке. Это НЕ
rollback journal: документ фиксирован и versioned
(`{"schema_version": 1, "initialized": true}`, независимая версия
схемы witness, схема самого journal JSON не менялась), без records/hash.
Witness создается crash-safely (temp fsync → rename → parent fsync через
`AtomicFileWriter`, exclusive create, mode 0600), строго валидируется
(regular file, symlink и другие non-regular объекты отвергаются, точное
versioned содержимое, state-bound durability barrier
`ensureTargetDurableIfCurrentState`) и никогда не удаляется и не
переписывается FIC, в том числе при empty records: witness означает
«journal lifecycle инициализирован», а не «records существуют».

State table инициализации (`MutationJournal::initializeOrLoad`, единственный
operational entrypoint; сырой `load()` остаётся primitive для тестов и
live-reload):

```text
J missing + W missing  → virgin bootstrap: EXCLUSIVE-create (no-replace)
                         durable empty journal → durable witness → strict
                         final journal proof (порядок journal-before-witness:
                         crash между фазами восстанавливается через migration
                         path)
J exists + W missing   → migration / interrupted bootstrap:
                         loadExisting/prove journal → создать durable witness
                         → ПОВТОРНЫЙ строгий final proof journal; сам journal
                         документ НЕ перезаписывается
J exists + W valid     → нормальная загрузка: witness proof → loadExisting/
                         prove journal; lifecycle публикуется только после
                         proof обоих persistent-объектов
J exists + W invalid   → fail closed; journal не изменяется, auto-repair
                         witness запрещён (malformed witness — persistent
                         state anomaly)
J missing + W valid    → provenance loss: fail closed НАВСЕГДА, включая
                         после daemon restart; «manual provenance recovery
                         is required»
J missing + W invalid  → fail closed (persistent-state anomaly)
```

Concurrency: пустой virgin journal создаётся ТОЛЬКО через no-replace
(exclusive create, `renameat2(RENAME_NOREPLACE)` / non-replacing fallback).
Bootstrap никогда не заменяет journal, появившийся между probe и install:
если exclusive-create конфликтует (target занят), это классифицируется
повторным probe пути (не по errno-тексту) как «другой FIC instance выиграл
bootstrap» и persistent state table переоценивается заново (ограниченное
число попыток, затем fail closed). Чужой journal никогда не считается
«нашим пустым»: он загружается и валидируется через обычные строгие правила
(witness при этом принимает чужой валидный durable witness как успех —
semantics witness-race и journal-race различны). Это не cross-process
serializability: generic cross-process CAS у journal updates по-прежнему
нет; исправлен ровно один race — bootstrap больше не уничтожает
конкуррентно созданный journal.

`installed != durable` применим и к witness, и к virgin journal: rename-ok +
fsync-fail при создании сначала пытается transparent durability finish по
точному состоянию; при невозможности — fail closed, а следующий startup
попадает в migration path (J exists + W missing).

**Loaded vs lifecycle initialized** — два разных состояния:
`loaded` = документ journal разобран и доказан;
`lifecycle initialized` = witness-aware persistent state machine (journal +
witness + финальный strict proof journal) полностью завершена на данном
объекте. Сырой `load()` никогда не завершает lifecycle и не делает объект
operational; после завершённой lifecycle повторный `initializeOrLoad()` —
строгий live-reload (`loadExisting`): исчезнувший journal после
инициализации всегда fail closed, никогда — empty bootstrap (семантика
follow-up 6). Ошибка witness creation на том же объекте оставляет lifecycle
неинициализированным; retry `initializeOrLoad()` заново проходит
witness-aware state table, raw reload witness обойти не может.
`DaemonMutationJournal` публикует operational journal только после
`initializeOrLoad() && usable() && lifecycleInitialized()`.

**Ограничения witness**: удаление внешним actor'ом ОБОИХ файлов (journal и
witness) неотличимо от virgin install — более сильный trust anchor вне MVP
scope. Daemon restart сам по себе НЕ является recovery-механизмом: после
provenance loss ошибка требует ручного восстановления provenance, а не
перезапуска. Journal и witness — одна logical retention pair; отдельной
purge-логики пары пока нет (TODO: при появлении purge/retention операций
удалять/обрабатывать journal и witness атомарно как пару).

**`Indeterminate` блокирует все operational-решения, не только записи**.
`DaemonMutationJournal::tryGet()` возвращает non-null IFF journal существует
И `usable()` (loaded + `Healthy`) после всех recovery-действий — никогда
только потому, что `load()` вернул true. Если открытый singleton стал
`Indeterminate`, следующий `tryGet()` пытается lazy recovery через
исправленный durability-proven reload; при неудаче (включая случай
исчезнувшего journal-файла) возвращает `nullptr` с ошибкой «Mutation
journal is Indeterminate; successful durable reload/recovery of persistent
journal state is required». Так автоматически fail-closed блокируются apply,
rollback, disable ownership resolution и любые будущие journal-backed
consumers (включая read-based решения через `activeRecords()`/`records()` —
эти методы остаются raw inspection API для tests/debug, но operational
решения обязаны опираться только на `usable()` journal). WAL/SQLite не
вводятся: порядок temp write → temp fsync → rename → parent fsync
сохраняется.

Путь: `FIC_MUTATION_JOURNAL_FILE` (по умолчанию
`/opt/fic/db/mutation-journal.json`), настраивается как остальные product
paths. Формат — JSON:

```json
{
  "schema_version": 1,
  "next_id": 7,
  "records": [
    {
      "id": 3,
      "policy": {"module": "SYSCTL", "submodule": "Global", "policy": "..."},
      "resource": "kernel.dmesg_restrict",
      "backend": "sysctl",
      "status": "applied",
      "undo": {"action": "remove_managed_setting", "key": "...", "applied_value": "..."},
      "created_at_epoch": 0,
      "updated_at_epoch": 0,
      "error": ""
    }
  ]
}
```

Загрузка fail closed: отсутствующий или неизвестный `schema_version`,
битая структура, неизвестные enum-значения, дубликаты `id` приводят к отказу
от использования journal (rollback не выполняется, disable не маскируется
как успешный). Только реальное отсутствие файла означает пустой journal;
если файл существует, но не может быть открыт или прочитан (permission,
I/O), это ошибка загрузки — fail closed. Существующий нулевой длины файл —
повреждённое persistent-состояние: валидный пустой journal обязан содержать
корректную schema-структуру.

Каждая мутирующая операция journal'а имеет сильную гарантию in-memory
состояния: если `persist()` не удался, наблюдаемое состояние journal'а
остаётся логически идентичным состоянию до операции, включая порядок записей
и `next_id`. Повторная операция после неудавшегося persist видит исходную
активную запись (fail closed). Один ресурс может иметь несколько записей от
разных политик.

## Undo actions

Типизированные исполнимые действия (не описательные флаги):

* `UndoRemoveManagedSetting{key, appliedValue}` — SYSCTL и SUDO: удалить
  FIC-owned запись ключа из managed-файла; `appliedValue` — fingerprint
  последнего применённого значения для обнаружения drift. Ownership
  определяется содержимым FIC managed-артефакта, а не текущим effective
  source: внешняя запись (главный sudoers или другой include), перекрывающая
  FIC-запись, не мешает её удалению. Drift внутри managed-артефакта —
  `Conflict`. Для SYSCTL после удаления пересчитывается эффективное значение
  из оставшихся источников precedence и runtime sysctl приводится к нему
  (default не угадывается). Для SUDO результат обязательно валидируется
  `visudo`; FIC-owned файл, ставший пустым, удаляется.
* `UndoRemoveFirewallPolicy{policyName}` — удаление FIC-managed правила и
  обычная firewall reconciliation. Snapshot всего nftables ruleset не
  выполняется.
* `UndoRemoveSshManagedPolicy{policyName, directive, appliedValue,
  disabledMutationIds}` — SSH: ownership-release rollback FIC-managed
  артефактов в main `sshd_config` (`/etc/ssh/sshd_config` Debian/Ubuntu,
  `/etc/openssh/sshd_config` ALT). Все FIC-мутации выражены явными маркерами
  в самом конфиге: один top-level FIC managed block (в global section) с
  sub-block'ами политик и `FIC_DISABLED` wrapper'ы вокруг отключённых строк
  (multi-value директивы, например `Port`). Persistent rollback state живёт
  в маркерах; journal хранит только policy reference, точную applied-строку
  (ownership proof против ручных правок блока) и mutation id созданных
  wrapper'ов. Main `sshd_config` **не считается FIC-owned**: `Match` blocks,
  included-файлы и строки вне FIC-артефактов никогда не изменяются;
  full-file snapshot не хранится и не восстанавливается.

  **Ownership-release semantics**: SSH rollback does not reconstruct a
  historical pre-FIC configuration. It releases all currently existing
  artifacts that can be proven to be owned by the mutation: managed
  overrides are removed and existing `FIC_DISABLED` wrappers are unwrapped.
  Owned artifacts that disappeared externally are treated as already
  released and are not reconstructed from the journal. Unknown, duplicated,
  malformed or manually modified existing artifacts cause a conflict.

  По-русски: rollback освобождает текущую FIC-owned область управления, а не
  реконструирует прошлое состояние файла. Провенанс wrapper'ов —
  subset-семантика: каждый фактически существующий wrapper политики обязан
  быть доказан journal payload'ом; неизвестный id, дубликат id в файле или
  дубликат id в payload — `Conflict` (файл не изменяется, даже доказанные
  wrapper'ы не разворачиваются). Payload id, чей wrapper уже исчез извне,
  трактуется как уже освобождённый (`releasedIds`) и не является ошибкой
  rollback. Полное отсутствие FIC-артефактов мутации (нет блока и
  wrapper'ов) — `NothingToDo` с runtime reconciliation (`sshd -T` + reload
  активного сервиса). Ручная правка directive-строки managed sub-block'а
  (несовпадение с `appliedValue`) и любая malformed-структура маркеров —
  `Conflict`. Rollback выполняется общей conditional-транзакцией
  (conditional atomic write, durability, валидация `sshd -t/-T`, reload,
  compensation restore при провале).
  Все записи и откаты shared `sshd_config` выполняются через optimistic
  conditional write (`AtomicWriteOptions::expectedTargetState`): атомарный
  snapshot (inode, metadata, content) захватывается при чтении, и запись
  отказывает (`Conflict`/apply failure без перезаписи), если файл изменился
  между чтением и записью. Это **optimistic expected-target precondition**,
  а не полноценный filesystem CAS: между финальной проверкой и `rename()`
  остаётся малое residual race window против non-cooperating writer
  (известное ограничение). `AtomicWriteResult` различает «ничего не
  установлено» и «rename уже произошёл» (`installed`, `installedTargetState`
  — точное состояние temp-inode/content/metadata, опубликованное rename; в
  т.ч. при ошибке durability после rename `installed == true`).
* `UndoDisableDeviceFeature{feature}` — отключение category-level desired
  state DC и пересборка `99-fic-devices.rules` через device daemon;
  per-device пользовательские правила не затрагиваются.
* `UndoRemoveGrubManagedSetting{key, appliedValue}` — GRUB
  ownership-release rollback (см. раздел «GRUB rollback (OSS/Grub)»);
  payload доказывает только FIC-владение (key, appliedValue), топология
  хранения берётся из текущего platform profile и в journal не пишется.
* `UndoApplyDacPlatformBaseline{policyName}` — DAC hardening-политики
  (`systemcommandlock`, `blocking_user_access_to_system_files`):
  platform-baseline rollback (см. следующий раздел). Payload несёт только
  policy identity — доказательство того, что последнее изменившее состояние
  apply выполнил FIC; пред-FIC owner/group/mode не хранятся никогда.
* `UndoRemoveSssdManagedSetting{section, option, appliedValue}` — SSSD
  ownership-release rollback (см. раздел «SSSD rollback
  (IDENTITY_ACCESS/SSSD)»); payload доказывает FIC-владение setting'ом
  (section, option, appliedValue); предыдущее foreign значение не хранится.
* `UndoRestoreKerberosScalar{section, relation, appliedValue, beforeKind,
  beforeRawLine, sectionExistedBefore}` — Kerberos reversible structured
  edit (см. раздел «Kerberos rollback (IDENTITY_ACCESS/KERBEROS)»);
  payload хранит ТОЧНЫЙ before-state целевой relation (raw line или факт
  отсутствия), snapshot всего krb5.conf не используется.

## Platform-baseline rollback (DAC hardening)

DAC hardening policies `systemcommandlock` and
`blocking_user_access_to_system_files` do not restore historical pre-FIC
metadata. While enabled they enforce the security metadata declared by the
platform profile (`FileAccessRule::enforced`); on disable they transition
managed objects to the platform's declared baseline metadata
(`FileAccessRule::baseline`, provider target `baseline`, TCB baseline
fields). По-русски: откат DAC hardening-политик не восстанавливает
исторические права, существовавшие до FIC. При включённой политике
применяется enforced-состояние, при отключении — штатное baseline-состояние,
определённое platform profile для конкретного дистрибутива
(`/etc/crontab` 0600 → 0644 на Debian/Ubuntu; command binaries
0750 → 0755; ALT TCB остаётся ALT-native baseline == enforced).

Ключевые свойства модели:

* **Источник истины — `PlatformProfile`.** Все различия дистрибутивов живут
  только в профилях; rollback backend (`DacBaselineRollback`) получает
  готовый `DacPlatformConfig` через `RollbackExecutorDeps::dacOptions` и не
  содержит switch'ей по distro id.
* **Отличие от ownership-release SSH** (см. `UndoRemoveSshManagedPolicy`):
  SSH rollback удаляет только доказанные FIC-артефакты и никогда не
  реконструирует исчезнувшие; DAC rollback — это **переход к platform
  baseline** каждого управляемого объекта, выполняемый по полной
  evidence-based проверке текущего объекта. Изменение режима администратором
  после apply (0750 → 0700) — ожидаемый сценарий, а не `Conflict`:
  disable вернёт объект к baseline (0700 → 0755).
* **Отличие от conditional historical restore (SYSCTL/SUDO)**: SYSCTL/SUDO
  удаляют только FIC-owned запись и не трогают внешнее состояние; DAC
  rollback изменяет metadata объекта независимо от того, находился ли он в
  enforced-состоянии, — но только если объект безопасно идентифицирован.
* **Отличие от apply-time compensation**: journal-запись DAC — это
  persistent disable-time provenance (fact of FIC-owned mutation), а не
  snapshot для отмены незавершённой транзакции apply. Pre-attempt metadata
  нигде не хранится.
* **Fail-closed object safety.** Разрешение пути, allowlist final symlink,
  provider-target validation, тип объекта и `fstat`-postcondition — те же
  гарантии, что при apply. Небезопасный объект (подменённый symlink вне
  allowlist, неожиданный тип, неизвестный provider target) — `Conflict` до
  любой мутации.
* **Missing files**: `MissingFilePolicy::Ignore` semantics — отсутствующий
  объект не создаётся ради baseline (`/etc/securetty`, `/etc/hosts.allow`
  и т.п.); «nothing to restore for this resource», остальные ресурсы
  продолжают обрабатываться.
* **Partial failure**: один объект с ошибкой при успешных остальных —
  `Partial`; journal-запись остаётся активной (`RollbackFailed`), повторный
  disable повторяет rollback. Так как `baseline → baseline` — no-op,
  повторный rollback идемпотентен и завершается `Success`/`NothingToDo`.
* **Provenance.** Apply записывает `Prepared` `UndoApplyDacPlatformBaseline`
  до мутации (fail closed при недоступном journal), commit после изменившего
  состояние успешного apply, discard когда состояние не изменилось (запись —
  только доказательство реально выполненной FIC-мутации). Для legacy-apply
  без journal-записей ownership доказывается наличием enforced-состояния
  (владение enforced + mode не слабее enforced) при отсутствии объектов в
  «чужом» состоянии (ни enforced, ни baseline): доказано — rollback
  выполняется; всё в baseline — `NothingToDo`; чужое/небезопасное —
  `Unsupported` (disable запрещён).

## GRUB rollback (OSS/Grub)

GRUB-политики используют ownership-release модель: FIC владеет только
своим managed-артефактом, никаких previous-value restore и full-file
snapshot не существует. Расположение артефакта определяется ТЕКУЩИМ
platform profile (не journal):

* Debian/Ubuntu — FIC-owned drop-in
  `/etc/default/grub.d/zzzz-fic.cfg` (canonical format: header
  `# Managed by FIC. Do not edit.`, ключи в фиксированном порядке;
  опустевший файл НЕ удаляется — остаётся канонический header-only
  артефакт, см. ниже);
* ALT — FIC managed block в EOF общего `/etc/sysconfig/grub2`
  (маркеры `# FIC_GRUB_BLOCK_BEGIN version=1` / `END`, whitelist ключей
  `GRUB_CMDLINE_LINUX`, `GRUB_DISABLE_RECOVERY`, `GRUB_TIMEOUT`,
  canonical order, строгий fail-closed парсинг: дубликаты/вложенные/чужие
  FIC-подобные маркеры, неизвестные ключи, malformed quotes,
  `$`/backticks — `Conflict`, файл не изменяется). Грамматика тела
  блока канонически строгая: принимается ТОЧНО форма `KEY="value"`,
  которую рендерит FIC (canonical re-encode equality), любые отклонения
  — пробелы вокруг `=`, ведущие/завершающие пробелы, инлайн-комментарии,
  нецитированный RHS — fail closed; допустимое значение всегда
  воспроизводится рендером байт-в-байт (render→parse→render round trip).
  Парсер сообщает типизированное размещение блока
  (`GrubManagedBlockPlacement`: `Absent` / `AtEof` / `NotAtEof`):
  `AtEof` означает, что после END-маркера нет НИКАКИХ foreign физически
  строк (canonical renderer их никогда не создаёт); валидный блок с
  foreign tail (присваивание, комментарий, даже пустая строка после END)
  остаётся PARSE-VALID (`NotAtEof`) — это proof OWNERSHIP, но не
  compliance (см. инвариант ALT EOF placement ниже).

Apply записывает в journal `Prepared`-запись ТОЛЬКО при реальном изменении
источника (`UndoRemoveGrubManagedSetting{key, appliedValue}`) и после
успешной записи коммитит `Applied`. Внешнее изменение FIC-managed значения
(drift) делает apply fail-closed. Любая мутация и откат выполняются под
общей `grubBackendMutex()`; обязательная пересборка grub.cfg выполняется
через `VerifiedProcessExecutor` (пустой environment, таймаут).

Дополнительные инварианты apply/rollback (обе топологии):

* ALT ownership vs compliance — для ALT-топологии «EXPECTED VALUE EXISTS
  INSIDE THE FIC BLOCK» НЕ достаточно. FIC block является действующим
  (effective) override-слоем ТОЛЬКО в EOF: shell-семантика last
  assignment wins означает, что foreign присваивание после END-маркера
  побеждает значение FIC. Различаются два доказательства:
  - ownership proof — валидный FIC block содержит записанный key/value
    (размещение не требуется): достаточно для rollback
    ownership-release и для классификации journal-записи как владения;
  - compliance/effective proof — валидный FIC block содержит ожидаемое
    значение И блок находится в EOF. Инспекция возвращает
    `managedLayerEffective`, typed proof различает `Matches` и
    `Ineffective` (значение принадлежит FIC, но блок смещён с EOF),
    journal-классификация различает `After` и `Ineffective`. Валидный
    блок с foreign tail НЕ считается malformed — следующий apply
    докажет собственный блок, сохранит foreign байты и relocat'ит блок
    в EOF через JOURNALED-мутацию;
* needsChange/compliance predicate — решение о необходимости изменения
  (`Grub::applyGrubValue`) принимается ТОЛЬКО через единый
  `grubManagedValueCompliant()` (valid && found && value == expected &&
  managedLayerEffective), никогда через raw value-сравнение. Для ALT
  same-value блок NotAtEof → `needsChange = true`: `Prepared`
  создаётся ДО relocation, relocation идёт через существующий
  rewrite-mechanism (`setGrubManagedBlockValue`), который удаляет
  доказанный блок с прежней позиции, сохраняет foreign байты
  byte-exact и размещает canonical блок в EOF; для Debian
  `needsChange = missing OR value mismatch`;
* компенсация неполна без успешной компенсирующей пересборки — GRUB
  транзакция состоит из persistent source state И derived grub.cfg
  state. Успешный source restore сам по себе НЕ полная компенсация:
  если компенсирующая пересборка провалилась (или была не запущена из-за
  провала `validateGrubRebuildInputs()` перед ней), фиксируется typed
  `GrubSourceMutationState::CompensatedPendingRebuild`, а не
  `Compensated`. Journal lifecycle matrix различает ДВА происхождения
  Prepared-записи — FRESH PREPARED AND REUSED ACTIVE PROVENANCE ARE NOT
  THE SAME THING:
  - Fresh Prepared — до операции активной provenance не было, запись
    создана именно для этой операции;
  - Reused active provenance — до repair уже существовала активная
    запись (`Applied` / `Prepared` / `RollbackFailed`) того же
    logical mutation resource; repair ВРЕМЕННО переводит её в
    `Prepared` (тот же `MutationId`, payload не переписывается),
    запоминая pre-repair status и error только в памяти текущей
    операции. Вторая активная запись для того же resource никогда не
    создаётся. Матрица:
  - failure + `Unchanged` → Fresh: Prepared discard; Reused: восстановить
    pre-repair status и error (restore durable, payload не меняется,
    timestamps могут обновиться);
  - failure + `Compensated` (source восстановлен И компенсирующая
    пересборка успешна) → Fresh: Prepared discard; Reused: восстановить
    pre-repair status и error;
  - failure + `CompensatedPendingRebuild` (source восстановлен,
    компенсирующая пересборка провалилась) → Prepared ОСТАЁТСЯ
    активным (recovery всё ещё требуется; pre-repair status НЕ
    восстанавливается);
  - failure + `Installed` / `Indeterminate` → Prepared остаётся
    активным;
  - success + `Installed` → Prepared commit Applied (тот же
    `MutationId` для Reused);
  - success + `Unchanged` (defensive) → Fresh: discard; Reused:
    восстановить pre-repair status.
  Любая ошибка journal-коммита/discard/restore — fail closed
  (apply == false). Restore предыдущего состояния выполняется ТОЛЬКО
  внутри доказанно завершённой операции (система не изменена или полная
  компенсация удалась); transient previousStatus в persistent journal не
  пишется — крэш после перехода в `Prepared` оставляет обычную активную
  `Prepared`-запись, которую существующая recovery-модель уже умеет
  обрабатывать. Семантика одинакова для обеих топологий и обеих
  компенсационных topology Debian (существовавший drop-in / канонический
  header-only retained drop-in). Source после этого доказанно BEFORE;
  повторно возвращать source в Applied-состояние FIC не пытается —
  recovery уже умеет безопасно завершить reconciliation;
* Ineffective reconciliation не выполняет promotion — `Ineffective`
  доказывает OWNERSHIP, но НЕ Applied-compliance (блок смещён с EOF).
  После обязательной reconciliation-пересборки и свежей пост-классификации
  `Ineffective`:
  - тот же desired value → активная запись сохраняется БЕЗ перехода
    (`Prepared`/`RollbackFailed` НЕ promovятся в `Applied`,
    `Applied` НЕ трогается); управление возвращается обычному apply,
    который увидит non-compliant source, переиспользует запись как
    repair-Prepared, выполнит journaled relocation в EOF и закоммитит
    `Applied` только после свежего post-rebuild EOF proof;
  - value change → старое FIC-owned значение освобождается через
    `undoGrubManagedSetting()` (rollback ownership-release EOF не
    требует) БЕЗ промежуточного durable promotion в `Applied`, затем
    старая запись напрямую разрешается в `RolledBack` из текущего
    активного статуса. При провале release — fail closed, запись
    остаётся в предыдущем активном статусе;
* GRUB journal identity consistency — логическая идентичность GRUB
  mutation записи определяется (policy, backend, resource), а НЕ undo
  payload: `MutationRecord.resource == UndoRemoveGrubManagedSetting.key`.
  Payload обязан соглашаться с identity: несогласованность отвергается
  на load (journal fail closed), `prepareMutation()` отказывается
  persist/refresh такую запись. Repair-reuse ищет reusable record
  ТОЛЬКО по exact (policy, backend=Grub, resource) — wrong-resource
  записи не переиспользуются по payload key; `appliedValue` должен
  совпадать с desired значением repair. Malformed exact-resource запись
  — это НЕ «no record»: fail closed без fresh-record fallback и без
  source mutation. Более одной одновременно active записи одного
  identity — fail closed на load; historical resolved записи
  (`RolledBack` / `Detached`) того же identity допустимы и сохраняются.
* ALT EOF placement и post-rebuild proof — после КАЖДОЙ успешной
  пересборки `proveExpectedGrubManagedValue()` для ALT возвращает
  `Matches` только при: source valid/safe, FIC block valid, ключ
  существует, значение совпадает И блок в EOF. Если во время пересборки
  внешний писатель дописал foreign присваивание после FIC блока — proof
  `Ineffective`: changed apply → false, `Indeterminate`, Prepared
  активен; idempotent apply → false, `Unchanged`, journal-запись не
  создаётся;

* validated rebuild inputs — ПЕРЕД каждой пересборкой grub.cfg (apply,
  idempotent apply, все rollback-варианты, обязательная reconciliation
  пересборка) входные данные заново проверяются: существующие base
  defaults (Debian) и shared defaults (ALT) должны быть обычными
  несимлинковыми файлами без group/world-writable битов и с безопасной
  цепочкой каталогов; отсутствие base/shared допустимо. Для Debian
  дополнительно проверяется ТОПОЛОГИЯ `/etc/default/grub.d`: каталог и
  вся цепочка предков должны быть безопасными, каждый чужой `*.cfg` —
  обычным несимлинковым файлом без group/world-writable битов, и ни
  один чужой drop-in не должен сортироваться после `zzzz-fic.cfg`
  (update-grub подключает drop-in'ы в лексикографическом порядке, более
  поздний файл молча переопределил бы FIC-значения); отсутствие самого
  `zzzz-fic.cfg` легитимно. Нарушение —
  fail closed: пересборка не запускается, journal-запись не разрешается;
* canonical empty drop-in — удаление последнего FIC-owned ключа в
  Debian-топологии НЕ unlink'ает артефакт: вместо этого атомарно
  сохраняется канонический header-only `zzzz-fic.cfg` (только строка
  `# Managed by FIC. Do not edit.`). Это устраняет race между удалением
  файла и будущим пересозданием, исключает corner-case'ы компенсации при
  concurrent drift (артефакт всегда остаётся обычным файлом, owned FIC) и
  сохраняет stable ownership-доказательство; header-only файл инертен для
  update-grub. Отсутствующий артефакт (внешне удалённый) по-прежнему
  легитимное освобождённое состояние (`NothingToDo` после пересборки);
* компенсация initially-missing Debian drop-in — физическое отсутствие
  drop-in НИКОГДА не восстанавливается через unlink: check-then-unlink
  race-prone и может удалить конкурентную внешнюю замену пути (TOCTOU
  поверх проверки ownership). Если FIC создал `zzzz-fic.cfg` из
  отсутствующего состояния, а apply требует компенсации, нейтральное
  безопасное состояние — канонический header-only FIC-owned drop-in,
  записанный атомарной CAS-записью против ТОЧНОГО FIC-installed
  состояния (внешний писатель, вклинившийся между записью apply и
  компенсацией, детерминированно проваливает CAS — его байты не
  перезаписываются и не удаляются; фиксируется concurrent drift,
  `Indeterminate`, `Prepared` остаётся активным). После успешной
  компенсации ключ политики доказанно отсутствует, поэтому для apply
  caller'а это `Compensated`, и `Prepared` discard'ится;
* post-rebuild proof apply — успешная пересборка grub.cfg сама по себе НЕ
  доказывает, что managed-источник всё ещё содержит ожидаемое значение:
  внешний писатель может изменить источник, ПОКА выполняется пересборка.
  После КАЖДОЙ успешной пересборки выполняется свежая (fresh) проверка
  текущего on-disk managed-источника
  (`proveExpectedGrubManagedValue`: топология валидна/безопасна, ключ
  существует, значение совпадает) — никогда не reuse pre-rebuild
  snapshot'а. Changed apply (FIC уже выполнил мутацию источника):
  mismatch/missing/malformed/unsafe → apply false,
  `sourceState = Indeterminate`, `Prepared` остаётся активным,
  компенсация НЕ запускается (drift-источник может быть внешней мутацией,
  которая никогда не перезаписывается) — recovery классифицирует
  состояние при следующем apply. Idempotent apply (FIC источник в этой
  операции не менял): mismatch → apply false, `sourceState = Unchanged`,
  никакая journal-запись не создаётся и не разрешается. `Prepared` →
  `Applied` коммитится только при успешном post-rebuild proof;
  idempotent apply сообщает успех только при доказанных И pre-rebuild, И
  post-rebuild состояниях. Generated `grub.cfg` в качестве proof не
  используется — проверяется только FIC-owned source (drop-in / managed
  block); validated rebuild inputs остаются отдельной проверкой
  «безопасно ли запускать пересборку» и её не заменяют;
* typed probe managed-пути — отсутствие артефакта (ENOENT) — легитимное
  освобождённое состояние, но symlink/каталог/FIFO и другой не-regular
  артефакт, занимающий managed-путь, — это `Conflict` fail closed без
  пересборки, артефакт не заменяется (он мог появиться только извне);
* single-snapshot CAS — и apply, и откат строят CAS-precondition из ОДНОГО
  snapshot'а, захваченного `load()` (тот же snapshot, из которого парсился
  FIC block). Внешний писатель между snapshot'ом и атомарной записью
  (stale-read race) детерминированно проваливает CAS: запись не
  публикуется, внешние байты сохраняются byte-exact, apply/rollback
  завершается ошибкой, `Prepared`-запись discard'ится;
* journal reconciliation перед каждым apply классифицирует активную GRUB
  запись (Before/After/Ineffective/Drift/Invalid) по текущему состоянию
  managed источника, затем выполняет обязательную пересборку и ПОСЛЕ неё
  повторно доказывает классификацию. Drift/Invalid после пересборки —
  fail closed: journal-запись остаётся активной, новый `Prepared` не
  создаётся. `Ineffective` (записанное значение принадлежит FIC, но ALT
  блок смещён с EOF) разрешается по ownership как `After` — effective
  EOF placement восстанавливает следующий journaled apply, никогда не
  invisible-rewrite;
* ALT EOF-сепаратор — перевод строки между foreign-байтами и FIC block'ом
  при размещении блока в EOF является FIC-owned сериализацией: он всегда
  добавляется для непустого foreign-содержимого (в том числе уже
  заканчивающегося `\n`) и снимается при декодировании ровно один раз,
  поэтому foreign-байты без завершающего перевода строки (`"FOO=bar"`)
  восстанавливаются byte-exact после apply → rewrite → удаления. При
  relocating блока (foreign-байты после блока) позиция сепаратора
  неидентифицируема — ничего не снимается, foreign-байты сохраняются
  дословно.

Rollback семантика (обе топологии):

* ключ отсутствует или весь артефакт удалён — владение уже освобождено:
  обязательная пересборка grub.cfg всё равно выполняется, затем
  `NothingToDo` (инвариант crash-after-source-rollback);
* ключ присутствует с другим значением — `Conflict`, источник не
  изменяется, пересборка не запускается;
* key == appliedValue — ключ удаляется (опустевший артефакт остаётся как
  канонический header-only `zzzz-fic.cfg`, без unlink),
  удаление публикуется атомарной CAS-записью против захваченного
  pre-rollback состояния и доказывается после записи; только ПОСЛЕ
  успешной пересборки rollback считается успешным. EOF placement для
  ownership-release НЕ требуется: валидный блок, смещённый с EOF
  (foreign tail после END), остаётся доказанным FIC-owned — удаляется
  только ключ/блок, foreign tail сохраняется byte-exact;
* ошибка пересборки — conditional compensation восстанавливает точное
  pre-rollback FIC-owned состояние (только пока цель всё ещё является
  rollback-installed состоянием; при внешнем drift компенсация запрещена),
  выполняется компенсирующая пересборка, journal-запись остаётся активной.

## SSSD rollback (IDENTITY_ACCESS/SSSD)

Rollback-supported: только `sssd_offline_credentials_expiration` (explicit
whitelist; любая будущая SSSD-политика — Unsupported по умолчанию).

**Модель владения.** FIC никогда не редактирует foreign
`/etc/sssd/sssd.conf`. Все FIC-owned настройки SSSD живут в едином
FIC-owned drop-in `/etc/sssd/conf.d/zzzz-fic.conf` (root owner, mode 0600,
atomic writes, отказ от symlink/non-regular target). Основной файл остаётся
byte-for-byte неизменным и при apply, и при rollback.

```text
FIC-owned drop-in:
    /etc/sssd/conf.d/zzzz-fic.conf        foreign main config:
        # FIC managed configuration           /etc/sssd/sssd.conf  (read-only для FIC)
        [pam]
        offline_credentials_expiration = 30
```

**Apply** (`inspect → Prepared → atomic install → effective verification →
SSSD restart verification → Applied`):

* топология проверяется перед мутацией: любой foreign snippet, сортирующийся
  ПОЗЖЕ `zzzz-fic.conf` и определяющий target `(section, option)`, делает FIC
  drop-in неоднозначно effective — apply fail closed, чужие файлы не
  меняются;
* unsafe/malformed FIC drop-in — fail closed;
* если желаемое значение уже effective исключительно за счёт foreign
  конфигурации и FIC ничего не меняет — journal-запись НЕ создаётся;
* после persistent mutation подключается существующий `SssdRuntime`: активный
  SSSD перезапускается, postcondition проверяется, и только затем
  `Prepared → Applied`;
* смена значения активной политики (`30 → 60`) — ownership-safe release
  старой mutation (rollback backend) → старая запись `RolledBack` → свежая
  `Prepared` → apply → `Applied`; две активные записи одного logical identity
  невозможны; Conflict при release — fail closed.

**Rollback** (`ownership-release`):

* `AFTER` (option в FIC drop-in, value == appliedValue): удалить только
  target option; семантически пустой drop-in удаляется целиком; foreign
  `sssd.conf` и чужие snippets не меняются; прежнее foreign значение
  становится effective естественно (без хранения его в journal);
* `BEFORE` (option уже отсутствует) — source undo считается уже выполненным
  ПРЕДЫДУЩЕЙ попыткой отката только при отсутствии staged artifacts для
  точного managed path (`zzzz-fic.conf.fic-removing-*`). Если такой artifact
  есть либо каталог нельзя надёжно проверить, apply/disable fail closed,
  journal остаётся активным: foreign replacement мог остаться в staging
  после power loss. Иначе это НЕ завершает rollback: runtime-
  реконсиляция обязательна (перезапуск активного SSSD + верификация), и
  только затем запись завершается как успешно откатанная. Неудачный
  рестарт оставляет запись в `RollbackFailed`, повторный disable повторяет
  runtime-реконсиляцию (удалённый FIC drop-in не восстанавливается);
  то же постусловие обязательно при apply-recovery любой активной записи
  (`Prepared`, `Applied`, `RollbackFailed`) с отсутствующим source: до
  успешной runtime-реконсиляции запись не переводится в `RolledBack`;
* `DRIFT` (значение отличается / drop-in malformed/unsafe) — `Conflict`,
  ничего не менять.

**Инвариант rollback-lifecycle.** Source ownership release и runtime
реконсиляция — один жизненный цикл отката: отсутствие FIC option само по
себе не означает завершённый rollback. Активная journal-запись означает,
что операция отката обязана завершить ВСЕ свои постусловия.

**Proof-bound removal (анти-TOCTOU).** Удаление пустого FIC drop-in — не
`unlink(path)`: точное состояние цели доказывается через O_NOFOLLOW-
дескриптор (identity, metadata, содержимое), затем текущий directory entry
атомарно переименовывается в приватное имя, и удалённый объект повторно
доказывается против captured identity (dev/ino). Если между proof и rename
файл был атомарно заменён внешним актором, иностранная замена
восстанавливается byte-exact на исходный путь только если он свободен;
если там уже появилась третья версия, staged объект сохраняется отдельно,
а новая версия не перезаписывается. Оба переноса используют
`RENAME_NOREPLACE`: занятый private target также не перезаписывается.
Если атомарный no-replace rename недоступен, удаление fail closed.
После restore foreign replacement либо сохранения его в staging при
появившейся третьей версии FIC подтверждает итоговое состояние каталога
через `fsync` перед возвратом conflict. Ошибка fsync означает
indeterminate directory state; journal provenance остаётся активной.

Удаление считается durable только после `fsync` родительского каталога
после rename-away и unlink. Компенсационное exclusive recreate выставляет
owner/mode через открытый fd, затем подтверждает файл и новую запись
каталога через `fsync`; отказ любого барьера не считается завершённой
компенсацией и сохраняет активную provenance.

**Компенсация удаления** (rollback `Mode::RemoveFile` в транзакции):
recreate исходного содержимого разрешён ТОЛЬКО при доказанном ENOENT
(классификация Missing/Unreadable/Changed/Other, провал secure-read никогда
не трактуется как «файл уже удалён»); recreate — exclusive create
(O_EXCL, no-replace): чужой объект, появившийся между proof и созданием,
fail closed, никогда не перезаписывается. Unsafe (symlink/non-regular) и
unreadable цели — fail closed, provenance остаётся активной.

**Prepared → Applied recovery (SSSD и Kerberos).** Активная запись может
перейти `Prepared → Applied` ТОЛЬКО после свежего AFTER/postcondition
proof'а (crash между системной мутацией и коммитом journal):

* SSSD: drop-in свежо доказан как AFTER (option == undo.appliedValue ==
  желаемое значение, без конфликтующих later snippets) при same-value
  apply → обязательная runtime-реконсиляция (restart активного SSSD,
  без повторного persistent writer), свежий повторный proof persistent
  AFTER, затем тот же `MutationId` становится `Applied`. Новая запись не
  создаётся и recovery завершается без второго restart; для уже `Applied`
  same-value reapply только повторно читает source, без write и restart;
* Kerberos: fresh full-graph AFTER proof (relation ровно в ожидаемой root
  топологии, нет внешнего include-определения, нет дубликата, текущее
  значение == undo.appliedValue == желаемое) при same-value apply → тот же
  `MutationId` становится `Applied`; новая запись не создаётся;
  дальнейший same-value путь только повторно читает полный graph, но не
  вызывает structured setter;
* `RollbackFailed` НИКОГДА не promoted в `Applied` автоматически: семантика
  прерванного rollback не позволяет тихий apply-repair — same-value apply
  fail closed, а завершение rollback выполняется retry'ем disable через
  обычный executor lifecycle.

**Journal lifecycle решения используют только typed results** (например
`executePreparedFileChangeDetailed()` со статусами
`Committed/Compensated/CompensationFailed`): diagnostic error strings
никогда не являются источником lifecycle-решений. Все обязательные
string/boolean поля payload SSSD/Kerberos (`section`, `option`, `relation`,
`applied_value`, `before_kind`, `before_raw_line`,
`section_existed_before`) разбираются loader'ом структурно fail-closed
(`find()` + `is_string()`/`is_boolean()`): non-string JSON значение — это
normal false-возврат без исключений; semantic validators остаются
отдельными.

## Kerberos rollback (IDENTITY_ACCESS/KERBEROS)

Rollback-supported: только `kerberos_ticket_lifetime` (explicit whitelist).
FIC-owned drop-in НЕ используется: target — relation
`[libdefaults]/ticket_lifetime` в root `/etc/krb5.conf` (foreign main
config), редактируемая structured edit'ом с сохранением существующего
conservative parser/include-graph подхода.

**Apply** (`inspect exact BEFORE → Prepared → CAS/atomic structured edit →
reparse full profile graph → effective verification → Applied`):

* full profile graph обязан парситься; target relation не должна быть
  определена во внешнем `include`/`includedir`; duplicate/ambiguous target в
  root — fail closed; чужие include-файлы никогда не редактируются;
* payload фиксирует ТОЧНЫЙ before-state: `Present` + исходная raw строка
  (включая indentation и `*`-маркеры key-final/value-final), либо `Missing`
  + `sectionExistedBefore`; snapshot всего `/etc/krb5.conf` не хранится;
* если effective target уже равен желаемому значению через foreign
  конфигурацию — journal mutation не создаётся;
* смена значения активной политики — как у SSSD: ownership-safe release
  (inverse delta) → `RolledBack` → свежая `Prepared` → `Applied`; Conflict
  при release — fail closed.

**Rollback** (inverse delta + CAS, классификация против journal):

* топологический drift (target появился во внешнем include, дубликат в root,
  raw-строка изменилась несовместимым образом) — `Conflict`, ничего не
  менять (например, admin `2h` никогда не перезаписывается recorded `8h`);
* `beforeKind == Present` и текущее значение == appliedValue — восстановить
  ТОЧНУЮ исходную raw строку (indentation, `*`-маркеры); после записи —
  reparse full graph и проверка восстановленного before-state;
* `beforeKind == Missing` и текущее значение == appliedValue — удалить
  relation; если journal доказывает, что section создан FIC
  (`sectionExistedBefore == false`), section header удаляется только когда
  структурно доказано, что он теперь пуст;
* текущее состояние уже совпадает с recorded before-state — `NothingToDo`.

**Инвариант владения.** Для Kerberos ownership существует ТОЛЬКО при
активной journal-записи. Без активной записи FIC не владеет никакими
изменениями `ticket_lifetime`: повторный disable (в т.ч. после
завершённого rollback перед обновлением policy status) и disable после
легитимного no-op apply завершаются `NothingToDo` — disable разрешён.
Foreign relation / root-определение без активной записи НИКОГДА не
трактуется как неявная provenance FIC; legacy-FIC владение не
восстанавливается (migration out of scope).

## PAM capability topology rollback (IDENTITY_ACCESS/PAM)

Автоматический rollback разрешён только для `enable_authentication_lockout`,
`enable_password_history`, `enable_password_quality`. Journal payload
`UndoDisablePamCapability` содержит capability, native topology kind и полный
домен FIC activation identifiers; содержимое PAM-файлов и foreign rules не
сохраняются. Logical resource — `capability/<policyName>`. Повторное apply
использует тот же active MutationId; смена faillock strategy переводит его
в `Prepared` до native transition, без промежуточного полного disable.
Payload содержит `had_applied_provenance`: recovery вправе удалить
`Prepared + Disabled` только для fresh записи, а не для reused provenance.
Для strategy transition payload также фиксирует прежнюю и целевую стратегии
и прежний error. Fresh transition содержит только target; reused provenance
обязана содержать exact pair previous/target, причём previous != target.
Один validator применяется writer и loader, поэтому невозможный для writer
reused payload не может быть принят после reload. Recovery сначала разрешает
именно эту durable операцию: точный BEFORE восстанавливает предыдущую
`Applied`, точный AFTER подтверждает новую `Applied`, а drift остаётся fail
closed. Только после этого применяется текущее desired value, которое могло
измениться после crash.

`Prepared` проверяется до обычного no-op: доказанный AFTER проходит свежую
структурную проверку и durability barrier, затем становится `Applied`;
доказанный Disabled для свежей записи позволяет discard; неоднозначное
состояние остаётся active и блокирует дальнейшее изменение. Полностью
компенсированная неудача reused transition восстанавливает предыдущие status
и error; при недоказанной компенсации запись остаётся `Prepared`.

Rollback сверяет payload с текущим platform profile и отказывается от
ownership-domain mismatch. Структурный drift effective topology сам по себе не
даёт права угадывать ownership. Для legacy `PamAuthUpdate` partial/mixed
комбинация известных FIC profiles остаётся invalid и для apply, и для rollback:
profile identifier не является причинным доказательством, поэтому release
fail-closed. Debian/Ubuntu AuthenticationLockout использует отдельную модель:
permanent pam-auth-update hooks являются инфраструктурой, а rollback
нейтрализует только strict FIC slot markers с exact journal mutation id. Crash-
partial subset допускается к release только при совпадении id; malformed/wrong
id — conflict. ALT использует существующие topology managers и их lock order.
`StaticVerifyOnly`
никогда не создаёт provenance и не запускает native deactivation. PAM provider
options (`PamOptionPolicy`, включая
`faillock.conf`/`pwquality.conf`/`pwhistory.conf`) в этот rollback не входят.
Без active journal явно FIC-owned markers/selections
считаются orphaned provenance: disable отклоняется, автоматического
«усыновления» или разрушительного legacy rollback нет.
PasswordQuality на Debian/Ubuntu разделяет compliance и ownership: distro
profile `pwquality` может обеспечивать требуемую topology, но всегда остаётся
external и потому даёт no-op без journal. Когда activation действительно
нужна, FIC включает собственный profile `fic-pwquality`. Rollback отключает
только `fic-pwquality`; disappearance этого marker при сохранённом journal
означает release FIC-owned topology, даже если администратор затем включил
эквивалентный distro `pwquality`. Таким образом journal доказывает lifecycle
FIC mutation, а не превращает shared native identifier во владение FIC.
Старые записи, содержащие activation domain `pwquality`, не усыновляются:
несовпадение с текущим `fic-pwquality` domain даёт Conflict и требует ручной
reconciliation.
Чистые preflight failures происходят до создания `Prepared`. Доказательство
ALT password-history BEFORE при отсутствии managed topology не требует ещё
не созданного history storage.

`pam-auth-update` — внешний multi-file writer, не атомарный вместе с journal.
FIC перед переводом записи в `Applied` захватывает и подтверждает durable
состояние известного набора state/generated files (file fsync, parent fsync,
повторная проверка identity/content). Если это доказательство не проходит,
`Prepared` остаётся active; exit code утилиты сам по себе не является
durability proof. Это не даёт транзакционной атомарности произвольным
побочным файлам, которые будущая версия `pam-auth-update` может менять вне
известной topology: такие случаи требуют отдельной проверки профиля/ручного
recovery, а не восстановления historical snapshot.

## Enrollment и результаты

`rollbackEnrollment(PolicyRef)` возвращает:

* `Supported` (явный whitelist, без default-positive enrollment):
  * все `SYSCTL` policies;
  * `DAC/SudoEdit` managed Defaults (`sudo_env_reset`, `sudo_passwd_tries`,
    `sudo_securepath`, `sudo_timeout`);
  * `DAC/Mode_and_Owner` hardening-политики (`systemcommandlock`,
    `blocking_user_access_to_system_files` — platform-baseline rollback,
    см. одноимённый раздел); остальные `Mode_and_Owner` политики
    (`custom_mode_and_owner` и др.) остаются `NotEnrolled`;
  * `NET/SshEdit` (`ssh_port`, `ssh_max_auth_tries`, `ssh_root_login`,
    `ssh_pubkey_auth`);
  * `FIREWALL/HostFiltering` (`block_ftp`, `block_rdp`, `custom_rules`);
  * `DC/DeviceControl` category features (`block_usb_storage`,
    `block_printers_scanners`, `block_optical_drives`);
  * `OSS/Grub` (`grub_timeout`, `grub_cmdline_linux`,
    `grub_disable_recovery` — явный whitelist, см. раздел
    «GRUB rollback (OSS/Grub)»);
  * `IDENTITY_ACCESS/PAM` — только три capability activation policies,
    перечисленные выше;
* `Unsupported` — модуль в системе rollback, но автоматический откат не
  реализован: `sudo_require_authentication` (чужие NOPASSWD/PASSWD specs),
  `exclusive_firewall_control` (уничтожает внешнее состояние), DC
  non-category policies и **любая неизвестная политика** внутри
  rollback-enrolled submodule — будущая SUDO/FIREWALL policy никогда не
  становится автоматически rollback-Supported без собственной journal
  integration и undo-действия;
* `NotEnrolled` — все остальные модули: `disable` сохраняет прежнее
  поведение (legacy).

Результат отката — типизированный `RollbackStatus`:
`Success / NothingToDo / Conflict / Unsupported / Failed / Partial`.
`NothingToDo` означает, что активные записи не требуют отката: для SYSCTL
и SUDO — FIC-owned запись нет в managed-артефакте (внешнее состояние никогда
не трогается); для GRUB — FIC-owned ключ уже отсутствует в managed-артефакте
текущей топологии, но обязательная пересборка grub.cfg всё равно выполняется;
для SSH — у мутации не осталось ни одного существующего
FIC-owned артефакта (нет managed sub-block'а политики и `FIC_DISABLED`
wrapper'ов: внешняя очистка, предыдущий rollback + crash и т.п.); rollback
при этом всё равно выполняет runtime reconciliation (`sshd -T` + reload), либо
политика ранее уже была успешно отработана: resolved-запись (`RolledBack`
или `Detached`) в journal документирует, что FIC не владеет текущим
состоянием; историческая запись любого другого статуса fail-closed. Это
позволяет disable.
Для legacy-установок (политика ENABLE, journal пуст) FIC не угадывает
владение: provenance проверяется по содержимому FIC managed-артефакта
(не по effective source), и при наличии там ресурса возвращается
`Unsupported` (provenance unavailable), disable запрещается; при отсутствии
— `NothingToDo` с диагностикой. Для SSH managed-артефакта нет — роль
provenance-проверки выполняет сам главный `sshd_config`: присутствие
target-директивы в global section без journal-записей означает
`Unsupported` (даже при совпадении значения с политикой), отсутствие —
`NothingToDo`.

## Расширение

Новые backend'ы (например, fstab) подключаются добавлением
payload'а в `UndoAction`, ветки в `RollbackExecutor` и записи мутации в
момент фактического изменения ресурса — без изменений в `Policy` и без
новых виртуальных методов.
