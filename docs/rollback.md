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

Изменение желаемого значения при активной SSH-мутации (`expectedValue !=
undo.appliedValue`) явно отказывается (fail closed): файл и journal не
изменяются, rollback baseline сохраняется. Журнал не ретаргетируется без
полного crash-safe протокола (иначе крэш между rewrite journal и системной
записью создаёт неоднозначный provenance). Требуемый путь: disable →
изменить значение → enable. Retarget поддерживается в будущей
transactional-версии (TODO).

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
объекта (`loaded_ == false` и `Healthy`): `records = empty`, `nextId = 1`,
`loaded = true`, `Healthy`, directory durability отсутствующего файла не
требуется. Исчезновение ранее известного journal (объект уже был `loaded_`
или уже `Indeterminate`) НЕ эквивалентно empty journal: такой reload
завершается ошибкой «mutation journal disappeared during reload/recovery;
provenance cannot be treated as empty», объект остаётся `Indeterminate`,
старые in-memory записи сохраняются. Автоматическое восстановление
удалённого journal из in-memory состояния не выполняется (fail closed).
Жизненный цикл:

```text
fresh + missing                → Healthy empty journal (bootstrap)
Healthy + successful reload    → Healthy новый snapshot
Healthy + failed reload        → Indeterminate, старая память сохранена
Indeterminate + successful
  durable reload               → Healthy
Indeterminate + missing journal→ Indeterminate, fail closed
```

**`Indeterminate` блокирует все operational-решения, не только записи**.
`DaemonMutationJournal::tryGet()` возвращает non-null IFF journal существует
И `usable()` (loaded + `Healthy`) после всех recovery-действий — никогда
только потому, что `load()` вернул true. Если открытый singleton стал
`Indeterminate`, следующий `tryGet()` пытается lazy recovery через
исправленный durability-proven `load()`; при неудаче (включая случай
исчезнувшего journal-файла) возвращает `nullptr`
с ошибкой «Mutation journal is Indeterminate; successful reload or daemon
restart is required». Так автоматически fail-closed блокируются apply,
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
* `UndoRestoreSshDirective{parameter, appliedValue, occurrences}` — SSH: откат
  точной текстовой мутации FIC в global section (от начала файла до первого
  `Match`) shared-файла `sshd_config` (`/etc/ssh/sshd_config` Debian/Ubuntu,
  `/etc/openssh/sshd_config` ALT). Main `sshd_config` **не считается
  FIC-owned**: full-file snapshot не хранится и не восстанавливается,
  `Match` blocks и included-файлы не трогаются. Resource identity — это
  конкретная recorded-мутация директивы (target directive mutation), а не
  whole global section. Каждый элемент `occurrences` описывает одну мутацию
  вхождения директивы: `beforeLine` — исходная строка (`null` для строк,
  вставленных FIC — при rollback они удаляются), `afterLine` — строка после
  мутации FIC. Позиция вхождения не хранится отдельно: порядок вектора
  `occurrences` полностью выражает identity (mutation-local ordered
  representation). Дубликаты директив, заменённые/закомментированные FIC,
  восстанавливаются полностью; одинаковые `afterLine` (например несколько
  закомментированных `#Port 22`) допустимы.
  Drift detection — **mutation-local ordered projection** (whole-global
  fingerprint и независимый per-occurrence подсчёт строк не используются):
  строится упорядоченная проекция target resource (active-директивы keyword
  плюс строки, точно совпадающие с recorded BEFORE/AFTER строками), которая
  сравнивается целиком с recorded AFTER- и BEFORE-последовательностями:
  * проекция == AFTER-последовательность → FIC-мутация применена → откат;
  * проекция == BEFORE-последовательность → persistent undo уже применён
    (в т.ч. crash после file-undo, но до reload/journal update) → runtime
    reconciliation: валидация `sshd -T` и reload активного сервиса; только
    после успеха — `NothingToDo`, journal → `RolledBack`, disable разрешён.
    Провал валидации или reload оставляет запись активной и отказывает в
    disable;
  * ни то, ни другое (в т.ч. structural drift: число вхождений keyword не
    соответствует записанной мутации) → `Conflict` без записи в файл.
  Внешнее изменение другой директивы (в т.ч. сделанное другой FIC SSH
  политикой — у каждой политики свой keyword/resource) не блокирует откат и
  не восстанавливается; изменение после первого `Match` и во внешних include
  этому тоже не мешает. Абсолютные номера строк не являются идентификатором
  мутации: проекция заново строится по recorded AFTER/BEFORE-представлениям.
  Повторный apply при существующей активной записи работает через existing
  undo, а не generic apply: текущие вхождения сопоставляются с записанными
  слотами; owned drifted slot (active-директива того же keyword) ремонтируется
  до recorded AFTER при сохранении исходного BEFORE baseline; любые новые /
  untracked вхождения keyword дают **fail closed** — файл и journal не
  изменяются, никакая мутация не выполняется без предварительно записанного
  undo provenance. Effective-compliant состояние не присваивается FIC: если
  директива уже в AFTER-состоянии, файл не пишется, journal не меняется.
  После reverse-записи обязательны валидация `sshd -T` и reload активного
  сервиса; при провале восстанавливается pre-rollback содержимое **только при
  условии, что текущий файл — это точное FIC-installed state** reverse-записи
  (identity, metadata, content, полученные от rename, а не свежий snapshot):
  иначе восстановление отказывает, внешнее изменение сохраняется, запись
  остаётся активной, возвращается `Failed`.
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

## Enrollment и результаты

`rollbackEnrollment(PolicyRef)` возвращает:

* `Supported` (явный whitelist, без default-positive enrollment):
  * все `SYSCTL` policies;
  * `DAC/SudoEdit` managed Defaults (`sudo_env_reset`, `sudo_passwd_tries`,
    `sudo_securepath`, `sudo_timeout`);
  * `NET/SshEdit` (`ssh_port`, `ssh_max_auth_tries`, `ssh_root_login`,
    `ssh_pubkey_auth`);
  * `FIREWALL/HostFiltering` (`block_ftp`, `block_rdp`, `custom_rules`);
  * `DC/DeviceControl` category features (`block_usb_storage`,
    `block_printers_scanners`, `block_optical_drives`);
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
не трогается); для SSH — текущее состояние директивы совпадает с recorded
BEFORE (мутация уже фактически отменена, в т.ч. crash-recovery), либо
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

Новые backend'ы (PAM, GRUB, fstab, DAC и т.д.) подключаются добавлением
payload'а в `UndoAction`, ветки в `RollbackExecutor` и записи мутации в
момент фактического изменения ресурса — без изменений в `Policy` и без
новых виртуальных методов.
