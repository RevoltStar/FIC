# FIC: передача контекста

## Current base

- Ветка `main`, рабочее дерево содержит НЕ закоммиченные изменения
  (Step 7A PAM provider managed block + fixed six architectural defects + тесты).
- Baseline до задачи: `f54530d` (lift Debian 13 / Ubuntu 26.04 — в нём).
- Коммит НЕ делать без явного запроса пользователя.

## Current task

**Step 7A — generic precedence-aware managed block для shared PAM provider
configuration.** Реализован reusable primitive, ownership/provenance model
и exhaustive unit tests. Реальные политики (faillock/pwquality/pwhistory)
на primitive НЕ переведены — это Step 7B/7C/7D.

### Что реализовано (Step 7A)

Новые файлы:

- `fic/src/modules/identity_access/pam/PamProviderManagedBlock.{h,cpp}` —
  string-level primitive: strict grammar, parse/proof/mutations,
  journal-binding classification.
- `fic/src/modules/identity_access/pam/PamProviderManagedBlockFile.{h,cpp}` —
  file-фасад: trusted read, typed container state, snapshot-bound atomic
  write, container release decision (pure).
- `tests/fic/modules/identity_access/pam/PamProviderManagedBlockTests.cpp`
  (плюс `...FileTests.cpp`), `tests/fic/rollback/PamProviderManagedEntryJournalTests.cpp`.
- `tests/CMakeLists.txt` — 3 новых unit-таргета.

Изменённые:

- `fic/src/rollback/MutationRecord.h` — новый typed payload
  `UndoRemovePamProviderManagedEntry` (backend `Pam`, enum
  `PamProviderBlockPlacementContract`) в `UndoPayload` variant.
- `fic/src/rollback/MutationJournal.cpp` — serialize/deserialize +
  write/read-parity валидация (`remove_pam_provider_managed_entry`),
  расширены Pam-ветки `prepareMutation` и record-level load-валидации
  (новый payload или существующий `UndoDisablePamCapability`);
  существующие payload'ы не изменены.

### Физический grammar (version=1)

```text
# FIC_PAM_PROVIDER_BLOCK_BEGIN version=1 provider=<provider> lead=<none|newline>
# FIC_PAM_ENTRY_BEGIN version=1 policy=<policy> mutation=<id>
<key> = <value>
# FIC_PAM_ENTRY_END
# FIC_PAM_PROVIDER_BLOCK_END
```

* маркеры — строго canonical, с колонки 0 (допустимы только trailing
  CR/LF/spaces/tabs); reserved namespace `FIC_PAM_` детектится
  case-SENSITIVE (как в GRUB): любое упоминание вне canonical-формы —
  fail-closed conflict;
* `<provider>`/`<policy>` — identity tokens `[a-z0-9_-]+`;
* `<id>` — canonical decimal > 0 (leading zeros/знак/переполнение →
  fail closed); РОВНО `MutationRecord.id` записи journal, которая писала
  entry (физическая мутация identity в самом entry — ABA protection);
* body — строго `key = value`, value без CR/LF/NUL/'#'/trim-пробелов;
* внутри canonical structural portion ничего лишнего (никаких пустых
  строк/комментариев); duplicate (policy,key), duplicate physical
  mutation id, nested/duplicate blocks — fail closed;
* STRUCTURAL LEAD (граница разделителя): поле `lead=` объявляет
  принадлежность РОВНО ОДНОГО LF непосредственно перед BEGIN:
  `lead=newline` — LF вставлен FIC (EOF-размещение после непустых foreign
  байтов), декодер снимает ровно его, парсер fail-closed, если байт перед
  BEGIN не LF или BEGIN в offset 0; `lead=none` — ничего перед BEGIN не
  принадлежит FIC (ничего не снимается). Благодаря этому round-trip
  `foreign → блок → append X → relocate → remove == foreign+X`
  байт-точен по построению (без эвристик).

### Общий канонический валидатор

`parseCanonicalPamProviderEntryBody(body, key, value)` в
`PamProviderManagedBlock.h` — ЕДИНСТВЕННЫЙ валидатор тела; используют
physical parser, spec-валидация (`isValidPamProviderEntryValue`), journal
payload-валидация и ownership expectations. Ключ из тела обязан ТОЧНО
совпадать с `managedKey` (exact match; prefix-compare «deny_extra» vs
«deny» устранён).

### Ownership proof / ABA

Ownership одного entry = exact (provider, policy, managedKey, canonical
body, physical mutation id == journal id) + валидный блок + отсутствие
structural ambiguity. Совпадение `key=value` ownership'ом НЕ является.
Typed proof: `Owned / Absent / Lookalike / Drifted / ForeignProvider /
MalformedState`. Удаление: absent → idempotent no-op; lookalike (другой
physical id) или drifted body → typed refusal. `set...` отказывает при
существующем entry с другим mutation id; same id + новый body — легальный
refresh (journal refresh переиспользует тот же id).

### Placement / relocation

`view.atBeginning` (BEGIN в offset 0) и `view.atEnd` (END — последняя
физическая строка, trailing '\n' — FIC-owned terminator) независимы;
effectivePlacement enum: Absent/AtBeginning/AtEnd/Misplaced. Валидный блок
при displacement остаётся parse-valid и OWNED; контракт
`PamProviderBlockPlacementRequest{Beginning, End}` отдельный. Все мутации
переразмещают блок в запрошенную позицию (relocation = удалить proven
блок, сохранить foreign байты, канонически переставить).

### Byte-exact foreign preservation

BOF: block span включает trailing '\n' после END (renderer всегда его
пишет) → foreign = всё после блока. EOF: ровно ОДИН separator '\n' перед
BEGIN — FIC-owned (append'ится всегда при непустом foreign), на decode
стрипается один → foreign без trailing newline восстанавливается точно.
Misplaced: foreign до+после verbatim (позиция separator неидентифицируема).
CRLF/без-trailing-newline/пустой/whitespace-only — покрыты тестами
(add/update/remove/relocation round-trip).

### Container creation / provenance

`PamProviderManagedBlockFile::readForMutation(path,
PamProviderAbsentContainerDecision{FailClosed, CreateFicOwned}, ...)` —
typed ENOENT-classification через `inspectTrustedFile`; absent+FailClosed
→ отказ (файл НЕ создаётся; vendor fallback модуля не подавляется
случайно). `writeMutation` — atomic (temp+rename+dir fsync), 0644,
euid/egid (как PamOptionFile), для pre-existing — snapshot CAS
(`expectedTargetState`); stale → `stale=true`, ничего не заменяется;
durability failure → не success. `containerCreated=true` только когда
контейнер создан из proven-absent. Release-decision (pure, unlink — Step 7F):
`RetainUnproven` (проверка provenance ВЫШЕ foreign content) →
`RetainForeignContent` (только блок удалить) → `RemovableFicOwned`
(проверено provenance + после удаления блока пусто).

**Container provenance (Variant A, durable typed record):** provenance
выражен ОТДЕЛЬНОЙ journal записью с typed payload
`UndoOwnPamProviderContainer{providerName, configPath}` (action
`own_pam_provider_container`, submodule `PAM_CONTAINER`, backend Pam) —
она НЕЗАВИСИМА от lifecycle записи-создателя entry (уход создателя больше
не теряет доказательство). Guard'ы prepareMutation: Applied-provenance не
re-Prepare; вторая активная container-запись на тот же configPath (другой
provider) — fail closed; Prepared → Prepared refresh разрешён (тот же id).
Schema journal: `kSchemaVersion = 2` (без migration code).

**Metadata (P1):** pre-existing файл — `FileMetadataPolicy::PreserveExisting`
(uid/gid/mode администратора не переписываются; раньше форсировалось
EnforceProvided 0644); FIC-created — EnforceProvided 0644/euid/egid.
Stale-детекция `AtomicFileWriter::matchesExpectedState` сравнивает
mode/uid/gid — метаданные-изменения между snapshot и write дают stale=true.

### Journal binding / crash states

`classifyPamProviderJournalBinding(status, parse, expectation)` — матрица
recoveries с durable previous→target переходом:
`PreparedFreshAbsent` (fresh, entry отсутствует — запись (пере)пишется,
тот же id), `PreparedFreshTargetPresent` (ADOPT: crash после физической
записи до завершения journal — без нового mutation id), 
`PreparedUpdatePreviousPresent` (продолжить переход), 
`PreparedUpdateTargetPresent` (завершить как Applied), 
`PreparedConflict` (update+absent / lookalike id / drift / foreign
provider — fail closed), `AppliedExact`, `AppliedMissing`, `AppliedDrifted`.
Primitive не зависит от rollback layer (`PamProviderJournalMutationStatus`
— локальный enum, caller маппит `MutationStatus`).

### Concurrency contract

In-process сериализация домена: callers обязаны держать
`IdentityAccessPolicy::configurationMutex()` на весь read-prove-write
(тот же контракт, что у C2 coordinator). Межпроцессный lock для provider
config домена сознательно НЕ введён в 7A; stale-overwrite исключён
уровнем файла: snapshot CAS через `AtomicWriteOptions::expectedTargetState`
(optimistic precondition, residual window как в GRUB/SSH, см.
docs/rollback.md). Локальный `std::mutex` на instance не создавался
(не сериализует процессы).

### Rollback payload (Step 7B–7F contract)

`UndoRemovePamProviderManagedEntry{policyName, providerName, configPath,
managedKey, appliedBody, previousAppliedBody, placement}`; mutation id =
сам `record.id` (не дублируется). `previousAppliedBody` — durable
previous→target переход in-place refresh: пусто = fresh create; иначе
точный canonical previous body того же managed key (≠ appliedBody).
Refresh guard'ы prepareMutation: fresh-запись с previous body — отказ;
Applied/RollbackFailed refresh обязан нести текущий applied body как
previous; Prepared refresh обязан нести ТОТ ЖЕ previous (иначе отказ);
refresh сохраняет id и re-arms Prepared. `own_pam_provider_container` —
отдельный payload (см. Container provenance). Валидация write+read
parity: identity tokens, absolute configPath без CR/LF/NUL, managed key,
canonical applied body exact key, previous body, placement beginning/end;
поле `previous_applied_body` пишется ВСЕГДА, при загрузке обязательно
(fail closed). Identity: entry — resource == configPath, policy ==
policyName, module IDENTITY_ACCESS/PAM; container —
IDENTITY_ACCESS/PAM_CONTAINER/policy == providerName.

## Validation (фактически выполнено)

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=debian-13 -DBUILD_TESTING=ON`
  EXIT=0.
- Новые targeted: `ctest -R pam_provider_managed` → **3/3 PASS**
  (после фиксов: grammar lead, refresh guards, container provenance,
  metadata preservation).
- Targeted build `fic` (daemon, включает MutationJournal) — PASS.
- Полный CTest (`build-check`): **110/110 PASS** (1 skip:
  `command_hash_batch_tests`, окружение).
- `git diff --check`: выполнен, чисто.

## Remaining (Step 7B+)

1. 7B: перевод `pam_faillock` scalar-политик на primitive: caller должен
   на Prepared-состояниях использовать новую матрицу recoveries
   (PreparedFreshTargetPresent → adopt без нового id,
   PreparedUpdatePreviousPresent → продолжить переход, остальное → fail
   closed); fresh container-создание сопровождать подготовкой
   `own_pam_provider_container` provenance записи.
2. 7C: pwquality; 7D: pwhistory BOF; 7E: suppress/wrapper set-only false;
   7F: rollback executor wiring + package release + inter-process lock
   решение (если потребуется) + unlink FIC-created container.
3. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, Debian 12 pwhistory ModuleArguments.
4. Не коммитить без явного запроса.
