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

### Refresh normalization требует стабильной topology

Каждый SUDO refresh normalization требует ровно этой последовательности:

```text
Exact(previous) на graph ∪ previous ∪ target paths
  → durability ЭТОГО ЖЕ capture
  → стабильная @includedir topology
  → normalize
```

Topology guard стоит перед **каждым** production-вызовом
`normalizePreparedToPrevious()`: ветка `CompletePrevious`, ветка
`Indeterminate → compensateToPrevious()` и `resolveAfterFailedMutation()`.

### Topology failure при активной Prepared = FailClosed

`recoverPrepared()` **никогда** не возвращает `NotPresent`, если активная
Prepared-запись была найдена, но recovery не смог доказанно её
commit/normalize/discard: расхождение topology → `FailClosed`.

Это существенно, потому что `reconcile()` продолжает обычный flow на любом
результате, кроме `FailClosed`. `NotPresent` при неразрешённой Prepared привело
бы к minting новых wrapper ids поверх неразрешённой записи.

### Успешный no-op требует ДВЕХ независимых вещей

```text
- стабильный @includedir membership;
- свежий snapshot semantic proof, что активных scoped Defaults не осталось.
```

Topology identity **не** доказывает содержимое файлов. Внешний процесс может
переписать **существующий** member, оставив множество имён неизменным, и
активировать scoped `Defaults`, которого `plan()` не видел: `plan()` читает
graph snapshot, построенный раньше.

**Порядок authority важен.** Успешный no-op:

```text
fresh filesystem capture (graph ∪ owned proof paths)
  → ownership ReleaseSubset
  → no-active-scoped-Defaults semantic proof
  → FINAL @includedir topology verification
  → unchanged success
```

Topology verification стоит **последней** именно потому, что новый member
каталога не может быть обнаружен capture, построенным из ранее загруженного
graph: `captureProofAndGraphState()` знает только graph documents и journal
proof paths. Member, появившийся после capture, невидим semantic proof'у.
Поэтому проверка membership — последнее security-sensitive действие, и между ней
и `unchanged = true` не выполняется ни одного filesystem proof/read.

Ownership contract для no-op прежний: отсутствующий доказанный wrapper — это
допустимый externally released subset (`ReleaseSubset`). Но drifted, unknown,
duplicate и malformed wrapper, а также активный scoped Defaults, видимый только в
новом capture, — fail closed. Benious изменение байтов того же member без
активизации scoped Defaults (комментарий, global Defaults) no-op **не** ломает.

### Selective compensation — capture-first, не graph-only

`compensateToPrevious()` строит work inventory из
`captureProofAndGraphState(previous ∪ target)`, а **не** из graph-only
`globalInventory()`. Target-only wrapper, физически существующий на
journal-known `canonicalPath`, выпавшем из current include graph, обязан быть
компенсируемым: иначе компенсация не даёт работы, recovery отвечает
`FailClosed`, и запись **необратимо** застревает, поскольку каждый retry упирается
в тот же тупик. Safety при этом не нарушалась — ownership record оставался
активным, — страдала именно liveness.

### SUDO multiline parity: один shared logical-entry assembler

Parser и snapshot-bound semantic proof **не должны** по-разному понимать один и
тот же sudoers-файл. Оба используют единственный assembler:

```text
SudoersLogicalEntries::assembleSudoLogicalEntries()
  physical lines → SudoLogicalEntry { firstPhysicalLine, lineCount, text }
```

* `SudoersConfiguration::expandDocument()` строит из него include graph и
  ordered lines.
* `ScopedDefaultsTransaction::proveCapturedState()` принимает semantic решение
  по **logical entry**, а не по одной physical line.

Задача изменения — **дедупликация** semantics, а не её улучшение. Сохранён
прежний contract: trim → нечётное число trailing backslash означает
continuation → снять один terminal `\` → добавить ровно один пробел → append
trim следующей строки. Существующие quirks (в т.ч. два пробела при
continuation и сохранение backslash у последней строки файла) воспроизведены
дословно и закреплены unit-тестами.

**Physical bytes остаются authority** для ownership, `payloadDigest`, CAS и
byte-exact suppression. Logical entries используются только для sudoers
semantic classification и physical-span planning. Никакого
`digest(logical text)` в journal proof не появилось.

Wrapper span: `beginLine`/`endLine` — индексы **маркеров**, а suppressed
payload лежит строго между ними. Логическая entry целиком внутри payload
считается suppressed; entry, частично пересекающая границу обёртки, — это
форма, которую FIC никогда не создаёт, поэтому она **fail closed** с явной
диагностикой, а не угадыванием semantics.

**Multiline parity ≠ полная реализация sudoers grammar.** Это общий assembler
logical entries, а не завершённый sudoers-парсер.

### SUDO security proof = files + @includedir topology

Доказательство безопасности SUDO состоит из **двух независимых частей**:

```text
1. physical file state:
   graph documents ∪ journal proof canonical paths

2. @includedir topology state:
   exact eligible membership captured by SudoersConfiguration
```

Изменение **любого** компонента инвалидирует доказательство.

Файловое capture само по себе недостаточно: новый eligible member каталога может
появиться после `load()` и нести активный scoped `Defaults` или скопированную
FIC-обёртку, о которых не знает ни один capture path.

```text
loaded:   {10-base}
позже:    {10-base, 20-new}   → topology mismatch
```

Неважно, успели ли мы узнать содержимое `20-new`. Сам факт нового eligible
member инвалидирует старый proof. Удаление и rename — тоже изменение: план и
semantic proof построены по другому effective graph.

**Важно различать:**

```text
ordinary @include известного файла   !=   @includedir membership topology
```

Явный `@include /path/file` сам по себе известен graph/capture layer. Этот этап
касается только каталогов, меняющих membership.

Membership identity — **не** content identity: содержимое каждого member
проверяется обычным file capture/proof слоем. Topology отвечает ровно на один
вопрос: «тот же набор eligible physical members всё ещё составляет этот
`@includedir`?».

Topology записывается при каждом успешном `load()` и пере-проверяется перед
каждым security-sensitive journal transition: final apply commit, commit
существующей Prepared (`CompleteTarget`), fresh Prepared discard, previous
normalization и rollback `Success`/`NothingToDo`, а также перед успешным
no-op. Расхождение инвалидирует текущую попытку; внутреннего retry loop нет.

**Одна eligibility semantics.** Enumeration каталога (проверка существования,
directory safety, фильтр игнорируемых имён, лексический порядок) вынесена в
единственный `enumerateIncludedirMembers()`, который используют и `load()`, и
verifier. Parser и security-verifier не могут разойтись в трактовке
`@includedir`: игнорируемое имя никогда не создаёт ложный mismatch.

Ошибки каталога (стал не каталогом, symlink там, где запрещён, permission/I/O,
исчез) → **fail closed**. Исчезновение ранее известного каталога **не**
читается как «пустой каталог».

**Не заявляется** атомарный filesystem snapshot каталога: модель защищена от
реалистичной конкурентной модификации (admin, package manager, configuration
manager), а не от malicious root. Если во время enumeration coherent-результат
получить нельзя, enumeration возвращает ошибку и вызывающий код fail closed.

### SUDO ownership preflight — physical-path based

Ownership preflight для активного SUDO-владения **опирается на physical path, а
не на current include graph**.

Внешний процесс может удалить `@include`, пока journal всё ещё доказывает
владение обёрткой, физически оставшейся на её canonical path. Graph-only
inventory в такой момент молча перестаёт инспектировать ровно те файлы, на
которые journal претендует, и вернул бы `ok/unchanged` поверх недоказанного
владения.

Scope capture:

```text
current include graph  UNION  все canonicalPath из активных journal proof
```

На этом единственном snapshot доказывается владение:

* **global uniqueness** wrapper id по объединённому set — один id не может
  физически существовать в двух файлах;
* **per file** существующая обёртка доказывается активным proof, который
  называет **ровно этот** файл и **ровно** этот payload digest;
* **drift** (изменившийся payload), **relocated wrapper** (тот же id+digest в
  другом файле), **unknown id**, **duplicate** внутри файла и **malformed**
  маркеры — fail closed;
* **capture failure** (symlink, directory, permission, I/O) — fail closed и
  **никогда** не переклассифицируется в отсутствие: для этого существует
  типизированная absence primitive;
* физически исчезновение доказанной обёртки остаётся **already released
  subset** и ошибкой не является — существующий external-release контракт
  намеренно не переопределяется.

Durability здесь намеренно **не** требуется: preflight read-only, journal
transition не происходит.

Preflight обязателен и перед no-op, и перед любой новой мутацией, поэтому
недоказанное владение блокирует не только no-op: новое нарушение B не будет
запланировано и применено поверх недоказанного A.

**Нерешённая отдельная проблема:** discovery новых неизвестных файлов,
появившихся в `@includedir` и не известных ни journal, ни graph, этим
префлайтом не решается — для них у FIC ещё нет известного canonical path.

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
* `UndoReleaseSudoScopedDefaults{policyName, previousProofs, targetProofs}` — SUDO
  `sudo_disable_scoped_defaults`: снятие обёрток `FIC_SUDO_DISABLED`,
  которые FIC создал для контекстных `Defaults`. Исходные байты записи
  хранятся **внутри самой обёртки** (byte-exact, включая terminator-ы
  строк и continuation-строки), поэтому payload — это только
  **доказательство владения**, а не бэкап и не snapshot.
  Доказательство — пара `{wrapperId, payloadDigest}`: `payloadDigest` это
  SHA-256 от **точных подавленных байтов**, а `wrapperId` обязан иметь
  канонический вид `FIC-SUDO-<digits>-<digits>-<digits>-<digits>-<digits>`.
  Перед снятием обёртки digest **пересчитывается** из живого файла; при
  расхождении (ручная правка тела обёртки) rollback — это `Conflict` с
  **нулевыми** записями, а не активация чужого содержимого.

  `targetProofs` — полный набор текущего владения, `previousProofs` — набор,
  которым FIC владел до перехода. Инвариант: `previousProofs ⊆ targetProofs`
  (повторная сверка **наращивает** владение, а не заменяет его, поэтому ранее
  созданная обёртка никогда не теряет разрешение журнала). Обёртка, исчезнувшая
  внешне, считается уже освобождённым владением и никогда не
  пересоздаётся. Неизвестный wrapper id, drifted-маркеры или
  неатрибутируемая FIC-подобная обёртка без активной записи журнала —
  fail closed (`Conflict`/`Unsupported`). После восстановления выполняется
  `visudo` и повторная загрузка графа.
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
* `UndoRemoveUserCreationManagedPolicy{policyName, configKind, configPath,
  appliedAssignments, previousAppliedAssignments}` — ownership-release для
  `IDENTITY_ACCESS/USER_CREATION`. Payload содержит только точные строки
  FIC policy sub-block; foreign assignments, before-value и snapshot файла в
  journal не попадают. `configPath` не является authority: apply/rollback
  сверяют его с CURRENT `PlatformProfile` и ожидаемым route/key set.

  Все FIC sub-blocks одного physical config находятся в одном строгом
  `FIC_USER_CREATION_BLOCK` в logical EOF, потому что `/etc/login.defs`,
  `/etc/default/useradd` и `/etc/adduser.conf` используют last-wins semantics.
  Foreign bytes никогда не переписываются. Fresh compliant foreign state —
  no-op без journal/adoption. Refresh одного owned sub-block A→B выполняется
  одной snapshot-bound atomic replacement; `previousAppliedAssignments`
  существует только для crash recovery этой Prepared-транзакции.

  Rollback удаляет только exact journal-proven sub-block. Исчезновение блока
  означает external ownership release (`NothingToDo`), manual edit/malformed
  marker/orphan state — `Conflict`. Peer FIC sub-blocks остаются byte-for-byte,
  пустой top-level container удаляется. После release становится effective
  актуальное foreign значение, а не историческое. Supplementary groups — одна
  relation-level mutation. Для shadow 4.17 empty policy владеет EOF override
  `GROUPS=`: он очищает membership-массив, даже если `useradd -D` показывает
  stale display state от предыдущего непустого assignment.
  DebianAdduser empty state владеет только `ADD_EXTRA_GROUPS=0`.
* `UndoDisableDeviceFeature{feature}` — отключение category-level desired
  state DC и пересборка `99-fic-devices.rules` через device daemon;
  per-device пользовательские правила не затрагиваются.
* `UndoRemoveGrubManagedSetting{key, appliedValue}` — GRUB
  ownership-release rollback (см. раздел «GRUB rollback (OSS/Grub)»);
  payload доказывает только FIC-владение (key, appliedValue), топология
  хранения берётся из текущего platform profile и в journal не пишется.
* `UndoRemoveSssdManagedSetting{section, option, appliedValue}` — SSSD
  ownership-release rollback (см. раздел «SSSD rollback
  (IDENTITY_ACCESS/SSSD)»); payload доказывает FIC-владение setting'ом
  (section, option, appliedValue); предыдущее foreign значение не хранится.
* `UndoRestoreKerberosScalar{section, relation, appliedValue, beforeKind,
  beforeRawLine, sectionExistedBefore}` — Kerberos reversible structured
  edit (см. раздел «Kerberos rollback (IDENTITY_ACCESS/KERBEROS)»);
  payload хранит ТОЧНЫЙ before-state целевой relation (raw line или факт
  отсутствия), snapshot всего krb5.conf не используется.
* `UndoRemoveIdentityLoginDefsManagedPolicy{policyName, configPath, key,
  appliedLine, previousAppliedLine}` — shared `/etc/login.defs`
  ownership-release backend (см. раздел «Shared login.defs rollback»);
  payload доказывает FIC-владение одной canonical-строкой (key, exact
  applied line); foreign значение и snapshot файла никогда не хранятся;
  `previousAppliedLine` — только durable previous→target переход
  unresolved Prepared refresh (empty = fresh create). Валидация payload
  (write и read parity) использует общую таблицу
  `IdentityLoginDefsPolicySpec.h`: точное policy→key соответствие и точный
  canonical value domain политики (неверный key, `-0`/`+1`/`01`, выход за
  диапазон — reject и на записи, и на load).

## Shared login.defs rollback (IDENTITY_ACCESS: USER_CREATION + PASSWORD_AGING)

Все скалярные политики `/etc/login.defs` — семь штук: USER_CREATION
(`user_create_home` → `CREATE_HOME`, `user_create_private_group` →
`USERGROUPS_ENAB`) и PASSWORD_AGING (`password_min_age_days`,
`password_max_age_days`, `password_expiration_warning_days`,
`regular_user_uid_min`, `regular_user_uid_max`) — владеют своим состоянием
через единый shared backend `IdentityLoginDefs`
(`fic/src/modules/identity_access/shared/login_defs/`):

* **Ровно один FIC-контейнер на файл**, всегда в логическом EOF:

  ```
  #@FIC_IDENTITY_LOGIN_DEFS_BLOCK_BEGIN version=1@
  #@FIC_POLICY_BEGIN ref=IDENTITY_ACCESS/PASSWORD_AGING/password_min_age_days@
  PASS_MIN_DAYS 1
  #@FIC_POLICY_END ref=IDENTITY_ACCESS/PASSWORD_AGING/password_min_age_days@
  #@FIC_IDENTITY_LOGIN_DEFS_BLOCK_END@
  ```

  Каждый sub-block содержит ровно одну canonical-строку `KEY value`.
  Peer sub-block'и сохраняются byte-for-byte; foreign байты вне контейнера
  никогда не изменяются. Строгая FIC-грамматика не совпадает с native
  consumer-семантикой.

* **Native-effective reader**: отдельный reader
  (`effectiveValue`) реализует фактическую семантику shadow-потребителей:
  last-wins, ведущие пробелы/табуляции и комментарии игнорируются,
  assignment без значения не заменяет ранее полученное значение;
  target-like строка, которую нельзя доказуемо разобрать, — fail closed.
  Этим же reader'ом обязана пользоваться `loadExpected()` operational
  PASSWORD_AGING политик (bulk `chage`), а apply/rollback-решения
  принимаются на native effective состоянии кандидата.

* **Apply**: durable-target-first Prepared/Applied модель. CAS-write
  (`expectedTargetState`, no truncate+write), refresh `A → B` — одна
  физическая атомарная замена, контейнер всегда переносится в логический
  EOF с сохранением appended foreign байтов. Relation-валидация
  (`PASS_MIN_DAYS <= PASS_MAX_DAYS` кроме `MAX=-1`; `UID_MIN <= UID_MAX`)
  выполняется на native-effective состоянии кандидата. PASS-пара
  валидируется через signed long (`PASS_MIN_DAYS` 0..INT_MAX;
  `PASS_MAX_DAYS`/`PASS_WARN_AGE` -1..INT_MAX) с native missing-key
  семантикой (`PasswordAgingMissingKeySemantics`); UID-пара валидируется
  typed unsigned reader'ом в ПОЛНОМ диапазоне `uid_t` (без INT_MAX-капа),
  и missing/invalid UID peer в итоговом effective состоянии — fail closed
  ДО мутации (синтетических missing-key значений для UID не существует).
  `PASS_MAX_DAYS`/`PASS_WARN_AGE` допускают `-1` (unlimited). Shared lock —
  `IdentityAccessPolicy::configurationMutex()`.

* **Prepared-target recovery с recanonicalization**: если после crash
  после физической записи (Prepared, body = applied line) внешний append
  после FIC-контейнера сломал canonical placement (контейнер больше не в
  EOF) или native-effective авторитет, apply-путь реканонизирует ТОТ ЖЕ
  когерентный контейнер в логический EOF (peer raw-тела и foreign байты —
  byte-exact, одна CAS-замена, relation-пруф на реканонизированном
  кандидате) и завершает ТУ ЖЕ Prepared(target) запись в Applied — это
  канонизация одного durable-перехода, не новый semantic transition и не
  refresh (никогда не создаётся `Prepared(previous=target, target=target)`).
  Третье owned состояние (body изменён вручную, orphan peer) или invalid
  relation кандидата — `Conflict`/fail closed без записи.

* **Coherence proof**: каждый физический sub-block обязан быть доказан
  journal-записью (известная политика whitelist'а из 7 политик, identity
  payload/record/resource, body = applied line или durable previous-сторона
  Prepared refresh). Orphan/unknown sub-block, ручная правка owned строки,
  malformed/unknown FIC-маркер — `Conflict` без записи.

* **Rollback = ownership release, никогда историческая реставрация**:
  удаляется точный FIC sub-block, foreign значение (если есть) становится
  effective естественно. Последний released sub-block удаляет весь
  контейнер. Перед физическим release вычисляется candidate без sub-block'а
  и на нём валидируются relation'ы: если release создаёт invalid relation —
  `Conflict` fail closed (без скрытых workaround'ов; известное ограничение).

* **Enrollment**: пять скалярных PASSWORD_AGING политик и обе
  USER_CREATION login.defs политики — `Supported`; две operational
  PASSWORD_AGING политики (`password_aging_apply_to_existing_accounts`,
  `password_aging_enforce_for_root`) меняют живое состояние учётных записей
  через `chage`. Operational PASSWORD_AGING policies intentionally use a
  non-reverting `NotEnrolled` lifecycle: disable stops future enforcement
  and preserves the account aging state that exists at the moment of
  disable (`sp_min/sp_max/sp_warn` не изменяются, pre-FIC значения не
  восстанавливаются, per-user journal provenance / baseline / `chage`
  rollback для них не существует и не планируется). Неизвестная политика
  PASSWORD_AGING — `Unsupported` (disable fail closed, никогда не
  наследует silent `NotEnrolled`). No-record preflight
  (`inspectUnrecordedState`) доказывает когерентность ВСЕГО shared домена
  (тот же `proveCoherence`): malformed контейнер, orphan/unknown peer
  sub-block или same-policy sub-block без provenance — `Conflict` fail
  closed (unrecorded ownership); валидный peer без target-блока и чистый
  foreign файл — `NothingToDo`. Повторный periodic/manual apply disabled
  operational политики не выполняет enforcement (`PolicyApplyStatus::
  Disabled`, `apply()` не вызывается).

## Release-only lifecycle (DAC / Mode_and_Owner)

\`mode_and_owner_profiles\` — desired-state controller, intentionally not
enrolled in rollback. Пока policy активна, она управляет только logical objects,
явно перечисленными в value, и применяет выбранный для каждого object profile.

Удаление object из value и DISABLE означают release ownership: текущие
owner/group/mode не изменяются, undo record не создаётся. Отсутствующий object
не означает неявный \`object=system\`; system применяется только по явному выбору.
Это исключает как восстановление pre-FIC snapshot, так и автоматический переход
к platform baseline при disable.
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
даёт права угадывать ownership. Для legacy `PamAuthUpdate` даже exact
`fic-pwquality` / `fic-pwhistory`, а также partial/mixed комбинации известных
FIC profiles не являются причинным доказательством: old apply мог увидеть
selection, созданную другим actor после `Prepared`, и ошибочно принять её за
AFTER. Поэтому PasswordQuality/PasswordHistory profile backend временно
observation-only: он не создаёт новую topology selection и automatic rollback
не удаляет selected profile. Debian/Ubuntu AuthenticationLockout использует
отдельную модель:
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

### C2 joint password topology rollback (Debian 12 / Ubuntu 24.04)

Password Quality и Password History образуют ОДИН joint runtime topology
domain. Записи managed password slot writer'а (activation identifiers
`fic-password-quality-hook` / `fic-password-history-hook` /
`fic-password-history-initial-hook`, payload `UndoDisablePamCapability`,
topology `PamAuthUpdate`) распознаются как C2 password domain и
обрабатываются ДО legacy per-profile path. Rollback такой записи — это
ОДИН joint semantic transition через planner/executor к целевому joint
состоянию: освобождаемая capability → `false`, выжившая capability → её
текущий configuration intent (читается из `IDENTITY_ACCESS.conf` в момент
rollback — в disable-флоу конфигурация ещё не переключена). Никогда не
выполняется «удаление activation identifier'ов одной записи» и никогда не
используется old two-profile disable: это осиротило бы выживший history
consumer (invalid topology). Variant switch (например Q+H → H-only при
release quality) выполняется нормальной planner-последовательностью
(DetachHistoryConsumer → DetachQuality → AttachHistoryInitial), повторный
запрос quality — DetachInitial → AttachQuality → AttachConsumer.

Отсутствие joint wiring (`RollbackExecutorDeps::
pamPasswordTopologyTransition` / `.pamPasswordRequestedState`) — fail
closed (`Conflict`). Failure перехода или компенсации →
`RollbackFailed` (запись НИКОГДА не помечается `RolledBack`); повторный
rollback после `RollbackFailed` остаётся fail closed до ручного
recovery provenance. Foreign stock pwquality не удаляется и не
претендуется: release FIC quality при появившемся stock producer даёт
итоговую semantic topology `ForeignQuality`. Whole-file restore
`common-password` не выполняется (pam-auth-update остаётся владельцем
generated stack). Передача desired state и provenance (which record owns
what): slot-записи — physical slot provenance; отдельного policy-level
undo record нет — joint requested-state target восстанавливается из
детекта домена + configuration intent.


`pam-auth-update` — внешний multi-file writer, не атомарный вместе с journal.
FIC перед переводом записи в `Applied` захватывает и подтверждает durable
состояние известного набора state/generated files (file fsync, parent fsync,
повторная проверка identity/content). Если это доказательство не проходит,
`Prepared` остаётся active; exit code утилиты сам по себе не является
durability proof. Это не даёт транзакционной атомарности произвольным
побочным файлам, которые будущая версия `pam-auth-update` может менять вне
известной topology: такие случаи требуют отдельной проверки профиля/ручного
recovery, а не восстановления historical snapshot.

### Managed history module arguments (Step 6) — topology ownership vs option values

C2 password domain владеет двумя РАЗНЫМИ уровнями состояния, и rollback их
не смешивает:

1. **Topology ownership** — journal-записи managed password slot writer'а
   (Prepared → Applied → RolledBack) доказывают владение FIC-owned PAM
   identity (selection + canonical Active slot + mutation id). Rollback
   такой записи — joint semantic transition (раздел выше).
2. **Managed history module arguments** — `remember=N` и bare
   `enforce_for_root` в телах FIC-owned слотов `fic-password-history` /
   `fic-password-history-initial` (только platform mode = ModuleArguments,
   Debian 12). Authoritative источник значений — configuration intent
   (`password_history_depth`, `password_history_enforce_for_root` в
   `IDENTITY_ACCESS.conf`), НИКОГДА текущее тело слота.

Обновление опций активного слота (`updateC2HistoryOptions`) использует ТОТ
ЖЕ journal lifecycle: `prepareMutation` **обновляет (refresh) единственную
активную запись домена** (policy, backend, resource) — mutation id
сохраняется, тело слота переписывается с тем же id, но с новыми опциями,
fresh proof, запись возвращается в Applied. Отдельная запись на option
change не создаётся.

Rollback семантика option change следует существующему framework-контракту:
у FIC нет per-value «восстановить произвольное предыдущее значение» —
rollback записи домена выполняет joint transition к целевому состоянию
(освобождаемая capability → `false`). Тела FIC слотов при этом уходят в
canonical Neutral без опций; выжившая capability перечитывает опции из
configuration intent при следующем attach (новый attach всегда рендерится
из актуальных configured options). Foreign PAM state (`/etc/security/
pwhistory.conf`, `common-password`, stock profile, чужие строки
`pam_pwhistory.so`) option writer и его rollback НИКОГДА не изменяют.

**Applied = ownership; Prepared = exact lifecycle recovery binding.** Для
option update (и только для него) это различие имеет самостоятельную
семантику:

* journal-запись в состоянии Applied — это ownership: слот можно
  ре-рендерить, деактивировать, доказывать владельцем в planner'е;
* journal-запись в состоянии Prepared (exact binding: canonical Active
  слот + marker id = id записи + role-bound provenance) — это НЕ владение
  и НЕ авторизация detach. Prepared никогда не авторизует отсоединение
  identity; он авторизует ТОЛЬКО точное завершение lifecycle
  (`Prepared → Applied`) — recovery.

Runtime recovery (Step 6 follow-up, P1): сбой journal completion после
durable записи новых опций оставляет состояние *selected + canonical Active
+ exact Prepared*. Executor классифицирует это состояние ДО planner'а
(`recoverExactPreparedSelectedHistoryIfNeeded`) и завершает lifecycle через
writer-примитив `completeExactPreparedC2Slot` (role-bound proof + complete,
без перезаписи тела слота, без pam-auth-update, тот же mutation id, без
новых записей), затем требует свежее нормальное owned-состояние и только
после этого продолжает planner/transition. Любой другой selected-but-unowned
state (нет записи, чужой id, чужой role payload, malformed Active body,
RollbackFailed) по-прежнему fail closed ДО деструктивных мутаций. Сбой
самого completion оставляет состояние exact recoverable Prepared без
изменений topology — следующий apply может повторить recovery. Качество
(FicQuality) аналогичного runtime-состояния не имеет: attach завершает
journal до native selection, а сбой completion компенсируется (neutralize +
discard) до выбора профиля; unselected Prepared — зона package-release
recovery.

Platform-семантика: ModuleArguments option writer — production wiring
ТОЛЬКО Debian 12 (profile: `configurationMode=ModuleArguments`, evidence
`pwhistoryRemember` + `pwhistoryEnforceForRoot`). Остальные
PamAuthUpdate-платформы — Debian 13, Ubuntu 24.04, Ubuntu 26.04 — остаются
на `ProviderConfigFile` (`/etc/security/pwhistory.conf`, classic
option-policy path); joint password topology на всех четырёх lifted по
реальному gate evidence (Debian 13 и Ubuntu 26.04 — после их собственных
real C2/wiring/prerm/options gates). Real gate
`pam_pwhistory_options_gate.sh` выбирает flow по compiled-in platform
mode: ModuleArguments — production wiring (Debian 12); ProviderConfigFile —
production provider-config evidence (production option-policy write в
pwhistory.conf + functional reuse-window и enforce_for_root differentials);
ModuleArguments wiring на ProviderConfigFile-платформах НЕ заявляется.
`pwhistoryRemember`/`pwhistoryEnforceForRoot` — обязательные per-option
evidence gates на ModuleArguments-платформах: без соответствующего флага
reader'а desired-state fail closed (в том числе на default depth), а
support classification держит опцию ReadOnly.

Package-release (prerm) игнорирует желаемые значения опций: он освобождает
весь домен, финальные слоты — Neutral без pwhistory опций; proof владения
не зависит от конкретных `remember`/`enforce_for_root` значений.

## PAM provider managed flag rollback (Step 7E)

Step 7E добавляет journal-backed FIC-владение тремя set-only флагами
(`even_deny_root` в faillock, `enforce_for_root` в pwquality и pwhistory)
через `PamProviderManagedFlagExecutor` — ту же durable-target-first state
machine, что и managed entry (Step 7B), с undo-действием
`remove_pam_provider_managed_flag` (identity: provider, configPath,
managedKey, appliedEnabled, previousAppliedEnabled, placement,
suppressionIds, previousSuppressionIds).

Семантика состояний (upstream presence-flags — значение «false» в конфиге
не существует):

* desired=true → bare managed key внутри FIC provider block (запись
  `remove_pam_provider_managed_flag` с appliedEnabled=true и ПУСТЫМИ
  suppression-наборами); foreign-вхождения не трогаются — true эффективно
  независимо от них (entry outrank'ит по placement).
* desired=false → disabled sentinel (`# FIC_PAM_FLAG_DISABLED version=1
  key=<key>`) ПЛЮС canonical suppression wrappers вокруг КАЖДОГО
  подавляемого foreign-активного вхождения ключа. Foreign line никогда не
  удаляется и не хранится в journal: её точные байты живут внутри wrapper
  (`raw=`-суффикс); journal хранит только provenance id (s1, s2, ...) —
  permission set, а не backup manifest.

Rollback (Step 7F, раздел ниже) освобождает FIC entry и разворачивает
только текущие физически доказанные wrappers — foreign-состояние
возвращается естественно, байт-в-байт. Ids внешне освобождённых wrappers
канонизируются из provenance (никогда не реконструируются из journal) и
НЕ переиспользуются, пока активная запись ссылается на них (namespace id —
объединение физического файла и journal provenance).

Ключевые fail-closed инварианты (детали в
`fic/src/modules/identity_access/pam/PamProviderManagedFlagExecutor.h`):

* Applied refresh — no-op; физический дрейф доказанного состояния
  (AppliedDrifted), чужой mutation id на wrapper, неизвестный wrapper id,
  wrappers при enabled-состоянии — отказ без физических изменений.
* Fresh transaction никогда не адоптирует pre-existing entry/wrapper без
  journal provenance (ABA-защита).
* Prepared recovery: durable target завершается первым (та же запись id),
  затем — только при расхождении — reconciliation под текущий desired.
* Идемпотентность: точный повтор — AppliedNoOp; toggle false↔true идёт
  под ОДНОЙ активной записью (id стабилен весь lifecycle); wrappers
  освобождаются байт-в-байт (§42), новые foreign-строки при disabled
  получают новые ids (§39/§72), старые стабильны.
* Metadata (владелец/права) primary-конфига сохраняется каждой физической
  мутацией.

## Package-removal C2 domain release (prerm)

Rollback политик (раздел выше) и удаление пакета — разные операции с разными
целевыми состояниями. Runtime disable возвращает joint password topology
к предыдущему desired состоянию; **package removal всегда освобождает весь
C2 домен**: целевое состояние — `Q=false, H=false` (все три FIC password
identity detached, все три managed slot'а canonical Neutral, final semantic
класс `None` или `ForeignQuality`). Частичный «остаточный» topology при
удалении пакета не допускается.

Механика (Debian/Ubuntu prerm):

* сгенерированный prerm не содержит shell-логики паролей: он вызывает
  узкую maintenance-команду `fic --maintenance pam-password-prerm-prepare
  preflight|release` (единственный вызов pam-auth-update над password
  identity выполняет production transition executor внутри daemon binary);
* Stage A (`preflight`) — строго read-only: инспекция топологии + coherence;
  selected-but-unowned, unselected-owned и оба history-варианта с нарушением
  инвариантов — fail closed ДО любой мутации (prerm отказывает в удалении
  до остановки сервисов и любого pam-auth-update); Prepared-leftovers
  допускаются через виртуальное recovery с пересчётом классификации;
* Stage B (`release`) выполняется prerm'ом после остановки всех FIC writer'ов
  и batch remove'а постоянных hook-профилей: `ExclusivePidLock` на
  runtime lock-файл → recovery exact-id `Prepared` через
  `compensateC2ActiveSlot` + свежее структурное доказательство → ОДИН
  `executor.transition(false, false)` → независимый финальный proof
  (нет selections, слоты Neutral, нет generated includes, foreign producer
  сохранён);
* неудача release классифицируется: компенсация доказана —
  «pre-release topology proven restored» (retry возможен); компенсация
  недоказуема — CRITICAL «NOT proven restored», молчаливое восстановление
  запрещено;
* prerm всегда восстанавливает permanent hook infrastructure
  (`pam-auth-update --enable` четырёх постоянных hook-профилей) и НЕ делает
  shell-snapshot и shell-restore password selection: pam-auth-update
  остаётся владельцем generated stack, а C2 executor — владельцем joint
  перехода.

Код: `fic/src/modules/identity_access/pam/PamPasswordPackageRelease.{h,cpp}`;
wiring — `fic/src/main.cpp` (`pam-password-prerm-prepare`); генерация prerm —
`packaging/deb/build-fic-debian12-deb.sh`. Поведенческие и packaging-тесты —
`PamPasswordPackageReleaseTests.cpp` и `tests/integration/packaging/
PamPackagingChecks.py`.

## SUDO rollback (DAC / SudoEdit)

Две независимые модели владения; их нельзя смешивать.

**Managed scalar Defaults.** `sudo_env_reset`, `sudo_passwd_tries`,
`sudo_securepath`, `sudo_timeout`, `sudo_exempt_group_disable` пишут одну
глобальную запись `Defaults` в FIC-owned `/etc/sudoers.d/zzzz-fic`
(`UndoRemoveManagedSetting`). Чужие глобальные `Defaults` никогда не
редактируются. Если более поздний внешний источник перекрывает значение, apply
возвращает failure и компенсирует собственную запись.

**Source-edit wrapper.** `sudo_disable_scoped_defaults` запрещает все четыре
формы контекстных `Defaults`:

```
Defaults:user ...      Defaults@host ...
Defaults>runas ...     Defaults!command ...
```

FIC намеренно **не вычисляет** семантику scoped Defaults: не разрешает
`User_Alias` / `Host_Alias` / `Runas_Alias` / `Cmnd_Alias`, `%group`, netgroups,
отрицание и `ALL,!foo`. Само наличие активной scoped-записи является
нарушением — именно поэтому P0/P1 контекстные перегрузки и сложные P2
alias/negation случаи закрываются без построения evaluator'а sudoers.

Глобальная запись не может универсально отменить контекстную, поэтому нарушающие
записи временно деактивируются обёртками в том же файле:

```
#@FIC_SUDO_DISABLED_BEGIN policy=<policy> mutation=<id>@
#@FIC_SUDO_DISABLED_LINE@eol=<lf|crlf|none>@<исходная физическая строка>
#@FIC_SUDO_DISABLED_END policy=<policy> mutation=<id>@
```

`eol=` — явная provenance terminator'а подавленной строки. Framing обёртки
всегда завершается LF, поэтому запись без финального newline не сливается с
END-маркером, а её terminator хранится в метаданных, а не выводится из
физической строки обёртки. Digest считается от ORIGINAL-байтов
(`content` + оригинальные terminator'ы), поэтому ручная правка `eol` или тела
даёт digest mismatch (`Conflict`), а не silent normalization.

Несколько нарушений, несколько файлов и многострочные записи поддерживаются;
unrelated содержимое не меняется.

Владельцем этой транзакции является отдельный компонент
`SudoersScopedDefaultsTransaction`; `SudoersConfiguration` остаётся владельцем
парсинга, include-графа и конфигурационных примитивов. Семантический список
нарушений — не список физических мутаций: один и тот же физический диапазон,
видимый несколько раз (повторный `@include` одного файла), дедуплицируется
до **одной** цели и оборачивается **ровно один раз**. Перед первой записью
собирается **глобальный** инвентарь обёрток всего графа; один и тот же
`wrapperId` в двух разных файлах — `Conflict` с нулевыми записями, потому что
одна запись журнала не должна разрешать снятие двух обёрток.

Транзакция apply: загрузка графа → `visudo` → детекция → построение
физических целей → глобальная проверка инвентаря → проверка, что digest
каждой запланированной обёртки совпадает с digest байтов, которые FIC
сейчас подавит → `Prepared`-запись журнала (`previous` = текущее владение,
`target` = владение после перехода) → **state-bound** запись каждого файла
(`AtomicFileWriter::captureTargetState()` + `expectedTargetState`) → `visudo` →
перезагрузка графа → семантическая postcondition (активных scoped `Defaults`
нет) → commit.

Ошибки различаются двумя независимыми осями: причина
(`SudoScopedDefaultsResultKind`: Success / Conflict / Failed) и состояние ФС
(`SudoScopedDefaultsFilesystemState`: Unchanged / Compensated / TargetInstalled /
PartialOrUnknown). Судьбу `Prepared`-записи решает **только** состояние ФС:
`Unchanged` и `Compensated` доказывают отсутствие FIC-owned остатков и
разрешают discard; `PartialOrUnknown` требует оставить запись активной.
Причина `Conflict` сама по себе ничего не решает, поэтому pre-write conflict
(ноль записей) корректно освобождает `Prepared`.

Состояние выводится из транзакции **целиком**, а не из результата последней
записи: падение на втором файле не может сообщить «ничего не записано», пока в
первом установлена обёртка.

Компенсация тоже state-bound: она восстанавливает предыдущий content
**только** если файл всё ещё находится в установленном FIC состоянии.
Файл, изменённый извне после мутации FIC, сохраняется и не перезаписывается
старым содержимым FIC.

No-op (активных scoped `Defaults` нет) — тоже требует preflight: `visudo`
валиден, грамматика обёрток цела, глобальный инвентарь согласован и каждая
FIC-обёртка доказана **активной** записью журнала. Осиротевшая обёртка без
записи журнала даёт fail closed и **не усыновляется** (файл и журнал не
меняются). Тот же preflight выполняется перед **любой** мутацией, поэтому
существующая orphan/drifted-обёртка блокирует и reconciliation, а не только
no-op. Для канонического ресурса допустима не более чем одна активная запись
журнала; несколько записей — fail closed, а не конкатенация proof-множеств.

### Durability и нормализация refresh

**Видимое состояние не равно durable-состоянию.** Обёртка, наблюдаемая на
диске, могла быть опубликована `rename(2)`, после которого `fsync` родительского
каталога не завершился до сбоя. Поэтому любой переход журнала сначала
подтверждается state-bound барьером `ensureTargetDurableIfCurrentState()` по
файлам, которые авторизуют proofs (`canonicalPath` каждой proof'ы).

Правило для `Prepared` после классификации:

| состояние ФС | `previous` пуст | `previous` непуст |
|---|---|---|
| доказанно durable == target | commit существующей записи | commit существующей записи |
| доказанно durable == previous | **discard** (владения не было) | **normalize** в `Applied(previous)` |
| partial / target-only | компенсация → previous | селективная компенсация → normalize в `Applied(previous)` |
| неоднозначно | Prepared остаётся активной | Prepared остаётся активной |

`normalize` (`normalizeSudoScopedDefaultsPreparedToPrevious()`) переписывает
`Prepared(previous=P, target=P+F)` в `Applied(target=P)` на **том же** id.
Обычный `discard()` здесь недопустим: он удалил бы запись, пока физические
обёртки `P` остались на диске, то есть превратил бы их в осиротевшие.

Перед `commit`/`discard`/`normalize` **финальное доказательство владения**
перепроверяет весь `targetProofs`/`previousProofs` против живого глобального
инвентаря: id, `canonicalPath`, digest, отсутствие orphan/unknown/duplicate.
Проверка выполняется ПОСЛЕ мутации и reload, непосредственно перед переходом
журнала.

Rollback также не может стать `Success`/`NothingToDo`, пока released-состояние
(включая **отсутствие** обёртки) не подтверждено durable.

### Exact ownership proof vs Release-subset proof

Два РАЗНЫХ контракта доказательства, которые раньше были смешаны:

* **Exact** (`ScopedDefaultsProofMode::Exact`) — используется перед каждым
  переходом журнала, который **разрешает** запись (`Prepared -> Applied`,
  нормализация refresh). Здесь КАЖДЫЙ ожидаемый proof обязан физически
  существовать, по точному `canonicalPath`, с точным `payloadDigest`.
  Отсутствующая обёртка — провал, даже если она «исчезла внешне».
* **ReleaseSubset** — только для rollback/release. Отсутствующая обёртка,
  доказанная журналом, — уже освобождённое подмножество; но её отсутствие
  должно быть отдельно доказано durable.

`releasedIds` допустимы только в ReleaseSubset. Семантика Exact решается по
ВСЕМУ захваченному inventory, а не по одному файлу: proof, авторизованный в
`a.conf`, законно не имеет обёртки в `b.conf`.

### Единая snapshot generation

Ownership proof, семантическая проверка и durability barrier работают на
ОДНИХ И ТЕХ ЖЕ `AtomicTargetState`:

```
captureProofAndGraphState()      // весь graph + все proof paths
  -> proveCapturedState()        // парс wrappers ИЗ captures, exact/released,
                                 // глобальная уникальность, семантика
  -> proveCapturedStateDurable() // ensureTargetDurableIfCurrentState() по ТЕМ ЖЕ
                                 // captures
  -> journal transition
```

Capture set = **все** документы графа **∪** все `canonicalPath` из журнала.
Производный от старого wrapper inventory набор путей недопустим: файл, который
только что получил обёртку, иначе не попадёт в capture и не будет проверен на
дубликаты.

Отсутствие файла доказывается типизированным барьером
`ensureTargetAbsentDurableIfCurrentState()`. Ошибка capture **никогда** не
трактуется как отсутствие: symlink, каталог, отказ прав или I/O-ошибка ведут к
fail closed.

### Prepared classification — snapshot, не текущий граф

Классификация unresolved `Prepared` **не** опирается на текущий include-граф:
обёртка может физически существовать, но перестать быть достижимой через
`@include`/`@includedir`. Capture set поэтому равен
`graph ∪ previousProof.canonicalPath ∪ targetProof.canonicalPath`, а
сравнение идёт по полной identity `(wrapperId, canonicalPath, payloadDigest)`.
Совпадение id+digest при другом файле не является ни CompleteTarget, ни
CompletePrevious.

Классификация лишь выбирает ветку — она не является доказательством для
перехода журнала. Разрешение всегда требует отдельного strict proof.

Fresh `CompletePrevious` (previous пуст) обязан доказать **durable** отсутствие
target-владения перед `discard`: видимое «обёрток нет» не переживает
power-loss после незавершённого fsync каталога.

### Captured path = Present | Absent

Каждый запрошенный путь представлен явно: `Present` (доказанное точное
содержимое) либо `Absent` (доказанное отсутствие). Путь не может молча
исчезнуть из снимка. Ошибка capture (symlink, каталог, права, I/O) **никогда**
не переклассифицируется в `Absent`: capture возвращает ошибку, и вызывающий
код обязан fail closed. Barrier подтверждает `Present` через
`ensureTargetDurableIfCurrentState()`, а `Absent` — через
`ensureTargetAbsentDurableIfCurrentState()` (появившийся объект проваливает).

### FullyReleased

Третий режим доказательства: **ни одна** ожидаемая обёртка не существует
физически ни в одной точке захваченного графа, и не осталось
unknown/duplicate/владеющей обёртки. Требуется перед:

* `discard` свежего `Prepared` (единственный путь — `resolveFreshPreparedToNoOwnership()`);
* `RollbackStatus::Success` и `NothingToDo` — на том же снимке, чей
  durability затем подтверждается.

### Разрешение refresh Prepared после компенсации

Успешная механическая компенсация **не** разрешает нормализацию: она
доказывает только те файлы, которые FIC фактически переписал. Внешний процесс
мог изменить previous-обёртку в файле, которого транзакция не касалась.

Поэтому перед каждым `normalizePreparedToPrevious()` выполняется
snapshot-bound previous-resolution proof:

```
capture( graph ∪ previous paths ∪ target paths )
  -> Exact(previous), без требования семантики
  -> proveCapturedStateDurable(ТОТ ЖЕ capture)
  -> normalize
```

`Exact(previous)` на полном capture **сам по себе** доказывает всё
необходимое: каждый previous-wrapper существует ровно один раз, по точному
`canonicalPath`, с точным digest; любая уцелевшая target-only обёртка является
**unknown** wrapper для этого expected-набора и валит проверку; дубликаты,
drift и некорректные маркеры тоже проваливают.

`target` пути входят в capture обязательно: target-only обёртка могла выпасть
из текущего include-графа (изменение topology) и иначе была бы невидима.

`FullyReleased` здесь **не** используется: его контракт — терминальное
whole-policy освобождение (не должна остаться ни одной wrapper этой политики),
используемое для fresh discard и rollback `Success`/`NothingToDo`. Он
ошибочно требовал бы отсутствия и законно сохраняемого previous-wrapper A.

Доказательство (proof) однозначно привязано к тройке
`wrapperId + canonicalPath + payloadDigest`; `previous ⊆ target` сравнивается по
полной идентичности. Каталог-пример: wrapper пропал внешне — отсутствие само по
себе не durable, и только fsync родительского каталога делает его доказанным.

Восстановление после сбоя выполняется в начале следующего production-вызова
(`ScopedDefaultsLifecycle::recoverPrepared`) ДО любого планирования: существующая
`Prepared`-запись классифицируется по живой ФС — `CompleteTarget` (доказанно
завершена) → commit существующей записи без минтинга новых id; `CompletePrevious`
(доказанно не применялась) → discard и свежее планирование; `Indeterminate` →
попытка точной компенсации target-only обёрток к previous, иначе fail closed с
сохранением записи. Поверх неразрешённой `Prepared` новые id никогда не минтятся.

Rollback — ownership release: снимаются только те обёртки, которые ещё
существуют и чьи id **и digest** доказаны payload'ом. Обёртка, исчезнувшая внешне, —
уже освобождённое владение (`NothingToDo`), а не ошибка; повторный rollback
идемпотентен; откат одной политики не разворачивает обёртки другой; неизвестный
wrapper id, drifted-маркеры и orphan-обёртка без активной journal-записи —
fail closed. После отката выполняются `visudo` и повторная загрузка графа.
Snapshot всего `/etc/sudoers` не используется.

**Единственный владелец `exempt_group`** — `sudo_exempt_group_disable`
(глобальная `Defaults !exempt_group`). `sudo_require_authentication` больше не
переписывает `exempt_group=...`; он владеет только `NOPASSWD -> PASSWD` и
`!authenticate -> authenticate`. Два независимых владельца одного security
state означали бы две разные rollback provenance.

**Граф зависимостей.** Глобальные `Defaults`-политики остаются глобальными и не
становятся evaluator'ом scoped `Defaults`; зависимость от
`sudo_disable_scoped_defaults` гарантирует отсутствие контекстных override'ов:

```
sudo_env_reset          ┐
sudo_passwd_tries       ├─> sudo_disable_scoped_defaults
sudo_securepath         │
sudo_timeout            ┘
sudo_exempt_group_disable ─> sudo_disable_scoped_defaults

sudo_require_authentication ─> sudo_exempt_group_disable
sudo_securepath              ─> sudo_exempt_group_disable
sudo_passwd_tries            ─> sudo_exempt_group_disable
sudo_timeout                 ─> sudo_exempt_group_disable
```

`sudo_env_reset` намеренно **не** зависит от `exempt_group`: upstream
sudoers не показывает такой связи (`exempt_group` освобождает от требований к
паролю и `PATH`, но не от `env_reset`). Для `secure_path` и `passwd_tries`
зависимость подтверждена документацией upstream: «Users in this group are
exempt from password and PATH requirements», «Users in the group specified by
the exempt_group option are not affected by secure_path» и «the PASSWD tag has
no effect on users who are in the group specified by exempt_group».
`timestamp_timeout` — парольная гарантия с тем же основанием.

Обратная защита: обязательная зависимость включённой политики не может быть
отключена раньше неё (сначала отключаются зависимые). Скрытого cascade-disable
нет — отказ возвращает список зависимых политик.

## Enrollment и результаты

`rollbackEnrollment(PolicyRef)` возвращает:

* `Supported` (явный whitelist, без default-positive enrollment):
  * все `SYSCTL` policies;
  * `DAC/SudoEdit` managed Defaults (`sudo_env_reset`, `sudo_passwd_tries`,
    `sudo_securepath`, `sudo_timeout`, `sudo_exempt_group_disable`) и
    `sudo_disable_scoped_defaults` (ownership-release через
    `FIC_SUDO_DISABLED` обёртки, см. раздел «Undo actions»);
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
  * `IDENTITY_ACCESS/PASSWORD_AGING` — пять скалярных login.defs политик
    (`password_min_age_days`, `password_max_age_days`,
    `password_expiration_warning_days`, `regular_user_uid_min`,
    `regular_user_uid_max`) через shared backend
    (см. раздел «Shared login.defs rollback»); две operational политики
    подмодуля — `NotEnrolled` (намеренный non-reverting lifecycle, см.
    раздел «Shared login.defs rollback»), неизвестные — `Unsupported`;
* `Unsupported` — модуль в системе rollback, но автоматический откат не
  реализован: `sudo_require_authentication` (чужие NOPASSWD/PASSWD specs),
  `exclusive_firewall_control` (уничтожает внешнее состояние), DC
  non-category policies и **любая неизвестная политика** внутри
  rollback-enrolled submodule — будущая SUDO/FIREWALL policy никогда не
  становится автоматически rollback-Supported без собственной journal
  integration и undo-действия;
* `NotEnrolled` — все остальные модули. В частности,
  `DAC/Mode_and_Owner/mode_and_owner_profiles` использует release-only
  lifecycle: `disable` меняет только status и не меняет filesystem metadata.

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

## Managed provider runtime rollback (Step 7F, реализовано)

Step 7F замыкает PAM rollback roadmap: managed provider configuration
(assignments, set-only flags и FIC-created container provenance) имеет
полный runtime rollback через dedicated backend
`fic/src/modules/identity_access/pam/PamProviderRollback.{h,cpp}`.
`RollbackExecutor` выполняет только dispatch, status mapping и journal
lifecycle; PAM-специфическое физическое доказательство — в backend'е.

Неизменяемый принцип: provider rollback **освобождает FIC ownership**, а
не восстанавливает историческое значение администратора. Для assignment —
удаляется только точный FIC managed entry; для set-only flag — точный FIC
flag entry плюс разворачиваются ТОЛЬКО существующие wrappers, чья
provenance авторизована journal-записью. Foreign raw line не хранится в
journal, не реконструируется, возвращается только из физического wrapper
байт-в-байт; отсутствующий wrapper — externally released subset.

Status matrix (assignment):

* Applied/RollbackFailed — `appliedBody` есть ownership target state:
  exact entry → release; absent → `NothingToDo` (перед успехом
  проверяется отсутствие orphan FIC state той же identity); drift/wrong
  mutation id → `Conflict`. RollbackFailed рассматривается как ownership
  target state (previous body — historical provenance).
* Prepared fresh (previous пуст): `PreparedFreshAbsent` → `NothingToDo`
  (система физически не мутирована); `PreparedFreshTargetPresent` →
  release target; иначе → `Conflict`.
* Prepared refresh (previous задан): rollback НЕ обязан завершать target —
  цель disable это полностью освободить policy ownership, поэтому
  доказанно-присутствующая сторона (previous или target) освобождается;
  `PreparedConflict` → `Conflict`.
* Placement — не ownership: смещённый foreign content'ом валидный block
  остаётся FIC-владением и освобождается; foreign bytes байт-в-байт.

Flag rollback: физическое состояние должно строго соответствовать одной
из авторизованных ownership states (Applied/RollbackFailed — только
target candidate; Prepared — target плюс previous при заданном
`previousAppliedEnabled`). Существующие wrapper ids — подмножество
авторизованного набора (отсутствующие авторизованные ids допустимы,
неизвестные — `Conflict`); wrapper того же identity с чужим mutation id —
`Conflict`. Release выполняется ОДНИМ чистым контент-преобразованием
(`releasePamProviderManagedFlag`) и одной filesystem транзакцией.

Container provenance (`UndoOwnPamProviderContainer`):

* Последняя FIC entry/flag в файле + пустой результат release + Applied
  container provenance → **exact snapshot-bound conditional delete**
  (`AtomicFileWriter::removeIfCurrentState`: descriptor-relative
  fstatat/unlinkat, re-proof identity/metadata/content, parent fsync;
  stale → `Conflict`, replacement не трогается) → container → RolledBack.
* Unlink прошёл, но directory fsync не удался → `removed=true, durable`
  НЕ подтверждена: journal ownership НЕ разрешается, записи остаются
  recoverable (retry завершает lifecycle через durable absence barrier
  `ensureTargetAbsentDurableIfCurrentState` — появление объекта во время
  барьера fail-closed).
* FIC-created файл с foreign bytes → после durable write foreign-only
  состояния container → **Detached** (FIC навсегда отказывается от права
  удалить файл).
* Pre-existing файл (container provenance отсутствует/не доказана) →
  никогда не удаляется (RetainUnproven); удаляется только FIC
  serialization.
* Другие FIC entries в block'е → container provenance остаётся active.
* Prepared container provenance легализуется ТОЛЬКО строгим existing
  creation-witness proof против pre-release физического состояния.

Journal order (per policy record): физический release → durability proof
→ container resolution (если применимо) → Success/NothingToDo наружному
`RollbackExecutor`, который один помечает policy record RolledBack. Crash
после физического release до journal update классифицируется retry'ем как
already released (идемпотентно, никакой реконструкции).

Platform identity proof: перед каждой мутирующей операцией payload
journal-записи сверяется с ТЕКУЩИМ platform profile (provider kind/name,
configPath, managed key, placement contract) через тот же typed routing
helper, что использует apply (`pamProviderManagedEntryPlacement` —
единый source of truth, без третьего whitelist). Domain, который текущий
profile не подтверждает — `Conflict`.

Contextual enrollment: `effectiveRollbackEnrollment(policy, deps)`
сохраняет static enrollment всех существующих backend'ов; для
IDENTITY_ACCESS/PAM опционных политик разрешает текущий platform binding
и только реально managed ProviderConfigFile политику делает Supported.
Debian 12 pwhistory (ModuleArguments), ALT pwhistory (AltTcbManaged) и
passwdqc остаются вне provider rollback; неизвестная будущая PAM policy
сохраняет static fail-closed ответ (Unsupported). Caller и executor
используют одну shared enrollment модель.

Interprocess serialization: managed-entry apply, managed-flag apply,
provider rollback и package provider release Stage B делят ОДИН lock
domain — `ExclusivePidLock` на `<runtimeDir>/pam-provider-managed.lock`
(один глобальный PAM provider домен, не per-provider файлы). Публичные
API захватывают lock; внутренние `*Unlocked`-примитивы package release
выполняются под уже удерживаемым lock. In-process mutex не заменяет
interprocess lock.

## Package-removal managed provider domain release (Step 7F, реализовано)

`PamProviderPackageRelease.{h,cpp}` — отдельный от C2 (`PamPasswordPackageRelease`)
release домен для managed provider configuration:

* **Preflight** (Stage A) — строго read-only: загрузка healthy journal,
  перечисление активных provider entry/flag/container записей, валидация
  каждой против текущего platform identity, trusted read + strict parse
  всех известных provider primary, proof releasability чистыми
  примитивами, orphan-детекция (FIC_PAM_PROVIDER_BLOCK / FIC_PAM_SUPPRESS
  без активной journal provenance → fail closed), coherence container
  provenance. Никаких записей; lock не требуется.
* **Release** (Stage B, после остановки всех FIC writer'ов) — exclusive
  захват shared managed-provider lock, СВЕЖИЙ полный preflight (Stage A
  snapshot никогда не доверяется), детерминированный порядок (configPath,
  policy, managedKey, record id), container cleanup, независимый final
  proof (нет активных записей домена, нет FIC serialization на известных
  primary, foreign файлы сохранены, FIC-created пустые контейнеры удалены
  durably).

Journal semantics: каждый успешно released entry/flag → RolledBack;
container: deleted → RolledBack, retained foreign → Detached; несвязанные
записи не трогаются; journal файл никогда не удаляется. Failure —
монотонный ownership release: released записи остаются RolledBack,
конфликтующая остаётся активной, удаление пакета блокируется, retry
продолжает оставшиеся активные записи (в отличие от C2 release с его
compensation model).

CLI: `fic --maintenance pam-provider-prerm-prepare preflight|release` —
narrow root-only entrypoint без path/policy аргументов. DEB prerm
(`write_system_integration_symlink_prerm`) выполняет provider preflight
Stage A до любых side effects (вместе с C2 preflight) и provider release
Stage B после остановки writer'ов и batch remove, ПЕРЕД C2 semantic
transition (provider домен не зависит от pam-auth-update; отказ provider
release блокирует удаление до любых C2 мутаций). ALT p11 RPM `%preun`
выполняет provider preflight на actual erase (`$1 -eq 0`) до side effects
и provider release post-stop hook'ом после остановки сервисов; upgrade
никогда не запускает ownership release. Shell не содержит PAM parser'ов —
решение целиком в maintenance binary.

## Расширение

Новые backend'ы (например, fstab) подключаются добавлением
payload'а в `UndoAction`, ветки в `RollbackExecutor` и записи мутации в
момент фактического изменения ресурса — без изменений в `Policy` и без
новых виртуальных методов.
