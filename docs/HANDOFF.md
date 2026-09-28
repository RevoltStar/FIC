# FIC: передача контекста

## Current base

- Ветка `main`, рабочее дерево содержит НЕ закоммиченные изменения
  (Step 7A PAM provider managed block + тесты).
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
# FIC_PAM_PROVIDER_BLOCK_BEGIN version=1 provider=<provider>
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
  mutation id, nested/duplicate blocks — fail closed.

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
(проверено containerCreated + после удаления блока пусто). Provenance
выражен флагом `containerCreated` в payload'е записи, СОЗДАВШЕЙ файл
(без отдельной journal mutation); известное ограничение: если запись-
создатель ушла, доказательство пропадает — консервативно RetainUnproven.

### Journal binding / crash states

`classifyPamProviderJournalBinding(status, parse, expectation)` →
A `PreparedNoPhysicalEntry`, B `PreparedExactEntry` (exact recovery для
того же id возможна — foundation для 7B), C `PreparedConflictingEntry`,
D `AppliedExact`, E `AppliedMissing`, F `AppliedDrifted`. Primitive не
зависит от rollback layer (`PamProviderJournalMutationStatus` — локальный
enum, caller маппит `MutationStatus`).

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
managedKey, appliedBody, containerCreated, placement}`; mutation id = сам
`record.id` (не дублируется). Валидация write+read parity: identity
tokens, absolute configPath без CR/LF/NUL, managed key, canonical applied
body (= physical serialization), placement beginning/end. Identity в
prepareMutation/load: resource == configPath, policy == policyName,
module IDENTITY_ACCESS/PAM.

## Validation (фактически выполнено)

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=debian-13 -DBUILD_TESTING=ON`
  EXIT=0.
- Новые targeted: `ctest -R pam_provider_managed` → **3/3 PASS**.
- Полный build + полный CTest: `/tmp/fic-full-build.log`,
  `/tmp/fic-full-ctest.log` — см. фактический итог ниже (заполняется по
  завершении прогона).
- `git diff --check`: выполнен, чисто.

## Remaining (Step 7B+)

1. 7B: перевод `pam_faillock` scalar-политик на primitive (Prepared →
   physical mutation → fresh proof → Applied + exact recovery состояния B).
2. 7C: pwquality; 7D: pwhistory BOF; 7E: suppress/wrapper set-only false;
   7F: rollback executor wiring + package release + inter-process lock
   решение (если потребуется) + unlink FIC-created container.
3. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, Debian 12 pwhistory ModuleArguments.
4. Не коммитить без явного запроса.
