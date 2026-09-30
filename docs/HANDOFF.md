# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `dd99d66` («Follow-up к последнему коммиту №2»,
  родитель `85addf0`; в `dd99d66` закоммичен follow-up №2 — production
  write/read parity suppression-id authority, принят). Поверх HEAD —
  незакоммиченный **follow-up №3** (test-only: исправление regression
  fixtures, см. Current task). Коммит НЕ делать без явного запроса.

## Current task

**Follow-up №1 к Step 7E (закоммичен в `85addf0`):**
1. **P1 — fresh-transaction orphan-wrapper adoption.** Баг: canonical
   suppression wrapper того же identity (provider/policy/key), но с чужим
   mutation id (или без активной journal-записи) молча адоптировался
   fresh-транзакцией. Фикс: `FlagPhysicalInspection` получил
   `matchingIdentityWrapperIds` (identity отдельно от ownership);
   `inspectFlagPhysicalState` классифицирует identity → ownership
   (при `expectedMutationId==0` каждый identity-matching wrapper —
   `foreignMutationWrapper=true`); `applyFreshFlag` fail closed ДО
   `prepareMutation()` с диагностикой, перечисляющей orphan suppression
   ids («orphan FIC PAM suppression wrapper(s)… suppression id(s) s7…»).
   Инвариант: «Physical FIC state is never adopted from markers alone».
2. **P2 — suppression-id collision invariant в MutationJournal.**
   Load-side rebuild через `activeFlagAuthority`: Prepared =
   `suppressionIds ∪ previousSuppressionIds`, Applied/RollbackFailed =
   только `suppressionIds`, resolved (RolledBack/Detached) — never
   authority; сравнение ограничено `configPath` (per-physical-file
   namespace). Write/read parity: `prepareMutation` отказывает incoming
   flag payload, чья authority (target ∪ previous) коллидирует с активной
   Pam flag записью того же `configPath` (refresh-имая запись исключена —
   её старая authority освобождается).
3. **Парсер-фикс (обнаружен при валидации P1):**
   `parsePamProviderManagedBlock` публиковал `view.suppressions` только
   при наличии FIC-блока; wrapper'ы в файле без блока молча терялись из
   view (orphan-состояние было невидимо). Теперь suppressions
   публикуются всегда.
4. Include cleanup в `PamProviderManagedBlock.h` (дубликаты `<cctype>`,
   `<cstdint>`, `<string>`, `<vector>`).

**Follow-up №2 к Step 7E (закоммичен в `dd99d66`) — write/read parity
suppression-id authority:** load-side collision check уже был
status-aware, но write-side `prepareMutation()` использовал отдельную
status-слепую lambda (всегда target ∪ previous) и ошибочно считал
historical `previousSuppressionIds` уже Applied/RollbackFailed соседней
записи активной authority — валидный incoming transition,
переиспользующий этот id, ложно отвергался (fail-safe, но нарушение
заявленной write/read semantic parity: loader тот же persisted state
принимал). Фикс: единые shared helpers в `MutationJournal.cpp` —
`preparedPamFlagSuppressionAuthority()` (future Prepared: target ∪
previous) и `activePamFlagSuppressionAuthority(record, flag)`
(фактический статус записи); обе стороны используют ОДНУ модель.
Write-side regressions: Applied previous-is-historical → SUCCESS +
reload; RollbackFailed previous-is-historical → SUCCESS + reload;
active-target collision → FAIL; Prepared previous-is-authority → FAIL
(остался).

**Follow-up №3 к Step 7E (выполнен, не закоммичен) — test-only:** два
write-side regression-теста из `dd99d66` фактически не воспроизводили
старый status-blind баг: record A строилась fresh-переходом
(previous={}), поэтому переиспользуемый id никогда не был previous A, и
тест прошёл бы и на старом writer. Fixtures перестроены через легальный
same-id false→false refresh lifecycle: fresh {old} → Applied → refresh
(target {new}, previous {old}) → Applied (RollbackFailed-тест затем →
RollbackFailed). Добавлены same-mutation-id assert, pre-assertion
фактического payload A (статус + target + previous) ДО parity-assertion
и полные reload proofs (A Applied/RollbackFailed target+previous
сохранены, B persisted с target). Тесты теперь падают на pre-dd99d66
status-blind writer и проходят на shared status-aware реализации.

Step 7F НЕ начат.

### Accepted architecture / invariants

- Routing (синтаксо-осознанный): Flag-биндинги маршрутизируются ТОЛЬКО по
  7E-whitelist: faillock `FailedAuthenticationEnforceForRoot` → End;
  pwquality `PasswordQualityEnforceForRoot` → End; pwhistory
  `PasswordHistoryEnforceForRoot` + PamAuthUpdate → Beginning; foreign
  фича/топология/Assignment-синтаксис флага → nullopt. Assignment-
  whitelist 7B/7C/7D не изменился.
- Один lifecycle-элемент на policy: toggle false↔true под ОДНОЙ активной
  journal-записью (`remove_pam_provider_managed_flag`), id стабилен;
  освобождение wrappers — байт-в-байт; новые foreign-строки при disabled
  → новые ids, старые стабильны; внешне освобождённые ids канонизируются
  из provenance и НЕ переиспользуются, пока запись активна (id-namespace
  = файл ∪ journal).
- Applied refresh — no-op; дрейф (AppliedDrifted), чужой mutation id,
  неизвестный wrapper id, wrappers при enabled — fail closed. Fresh
  transaction не адоптирует pre-existing entry/wrapper (P1: и wrapper
  того же identity — до фикса адоптировался). Prepared
  recovery: durable target первым, затем reconciliation под текущий
  desired (semantic callback получает durable target ПЕРВЫМ).
- Absent primary → FailClosed (no create, no records); metadata
  сохраняется; no whole-file snapshot rollback.
- Journal payload `remove_pam_provider_managed_flag`: enabled-состояние
  ⇒ пустые suppression-наборы; fresh transition ⇒ нет previous
  provenance; write/read parity (previous_applied_enabled всегда
  materialized).
- **Suppression-id authority model (P2):** один suppression id —
  authority максимум ОДНОЙ активной flag записи одного физического файла
  (namespace = configPath). Единая status-aware модель
  (`activePamFlagSuppressionAuthority`): Prepared = target ∪ previous;
  Applied/RollbackFailed = target; resolved — never authority.
  `prepareMutation` оценивает existing records по их фактическому
  статусу, а incoming transition — как future Prepared (target ∪
  previous, `preparedPamFlagSuppressionAuthority`); refresh-имая запись
  исключена (её authority освобождается заменой). Одна модель на load
  и write (parity).

### Completed

- `PamProviderManagedFlagExecutor.{h,cpp}` (новые) +
  grammar/primitives в `PamProviderManagedBlock.{h,cpp}`
  (FlagEnabled/FlagDisabled kinds, sentinel, wrapper line/parse,
  `setPamProviderManagedFlagTransition`, icase-сканер активных
  вхождений pwquality/pwhistory, faillock — case-sensitive).
- Роутинг в `PamProviderManagedEntryExecutor.cpp` переписан
  синтаксо-осознанно (см. invariants).
- Journal: write/read parity flag payload + load-time cross-field
  identity check (исправлен баг: loader не имел flag-branch — любой
  restart с флаговой записью падал бы fail closed) + §32 load-time
  cross-record suppression-id uniqueness.
- Policy wiring: `PamOptionPolicy` / `PamProviderSemanticVerifier` —
  managed flag path; pwquality/pwhistory icase flag semantics;
  argv-конфликт флага → preflight fail closed до мутации.
- Fix в `PamProviderManagedBlock.cpp` (`parsePamProviderSuppressionWrapper`):
  mid-parse reset `wrapper = T{}` затирал уже присвоенный `provider`.
- Follow-up №1 (закоммичен в `85addf0`): P1 identity/ownership split +
  fail-closed fresh; P2 authority model load+write; парсер-фикс
  публикации suppressions вне блока; include cleanup.
- Follow-up №2 (закоммичен в `dd99d66`): единый status-aware authority
  helper load+write (устранён write/read mismatch), write-side
  regressions Applied/RollbackFailed previous-is-historical.
- Follow-up №3 (не закоммичен): исправлены regression fixtures —
  real same-id refresh с непустым previous set + reload proofs.

### Changed areas

- `fic/src/modules/identity_access/pam/PamProviderManagedBlock.{h,cpp}`
  (парсер-фикс publish-suppressions; include cleanup)
- `fic/src/modules/identity_access/pam/PamProviderManagedFlagExecutor.cpp`
  (P1: FlagPhysicalInspection/inspect/applyFreshFlag)
- `fic/src/rollback/MutationJournal.cpp` (P2: shared
  `preparedPamFlagSuppressionAuthority` /
  `activePamFlagSuppressionAuthority` — единая status-aware модель на
  load и в prepareMutation)
- `tests/fic/modules/identity_access/pam/
  PamProviderManagedFlagExecutorTests.cpp` (+3 теста: orphan wrapper
  refuse для desired=false/true, foreign-mutation-id fail-closed для
  обоих desired; helpers `forgeWrapperLine`/`writeOrphanWrapperState`)
- `tests/fic/rollback/PamProviderManagedEntryJournalTests.cpp`
  (+`testFlagSuppressionAuthorityInvariants`: load-side cases A–D,
  Applied-previous-not-authority, cross-file OK; write-side parity;
  follow-up №2: `testAppliedPreviousSuppressionSetIsHistoricalAtWriteTime`,
  `testRollbackFailedPreviousSuppressionSetIsHistoricalAtWriteTime`;
  follow-up №3: fixtures этих двух тестов перестроены через легальный
  same-id refresh с непустым previous set, добавлены payload/reload
  assertions)
- `tests/.../pam/PamProviderManagedEntryExecutorTests.cpp` (routing
  matrix синтаксо-осознанный), `IdentityPolicyHierarchyTests.cpp`
  (policy-path 7E), `tests/CMakeLists.txt` (в Step 7E)
- `docs/rollback.md` — раздел «PAM provider managed flag rollback
  (Step 7E)» (в Step 7E; follow-up внешних контрактов не менял)

### Validation (фактически выполнено)

- Полный build `build-check` (ubuntu-24.04) — 0 errors.
- Полный CTest — **112/112 PASS** (1 skip: `command_hash_batch_tests`,
  окружение).
- Targeted: `pam_provider_managed_flag_executor_tests`,
  `pam_provider_managed_entry_journal_tests`,
  `pam_provider_managed_entry_executor_tests`,
  `pam_provider_managed_block_tests`,
  `pam_provider_managed_block_file_tests`,
  `identity_policy_hierarchy_tests`, `pam_configuration_tests`,
  `pam_password_wiring_tests`, `pam_password_*`,
  `alt_pam_faillock_topology_tests`,
  `alt_pam_password_history_topology_tests` — все PASS.
- `git diff --check` — чисто.
- Follow-up №3 (поверх `dd99d66`, текущая сессия):
  - targeted build + run: `pam_provider_managed_entry_journal_tests`
    PASS, `pam_provider_managed_flag_executor_tests` PASS;
  - mutation check: временная подмена write-side вызова на
    `preparedPamFlagSuppressionAuthority(*otherFlag)` (эквивалент старого
    status-blind writer) → journal-тест упал на основном assertion
    (`suppression id 's1' ... already provable rollback authority of
    active record 1`); production-файл восстановлен через
    `git checkout --`, реального изменения нет;
  - полный build `build-check` — 0 errors; полный CTest — **112/112
    PASS** (1 skip, тот же);
  - `git diff --check` — чисто.
- Distro E2E НЕ запускался (до 7F).

## Remaining

1. 7F: rollback executor wiring + package release + unlink FIC-created
   container (snapshot-bound conditional-delete primitive НЕ существует).
2. PAM argv override на production daemon harness end-to-end не
   прогонялся (покрыт preflight/policy-level regression).
3. Прод-apply на absent primary отказывает (FailClosed); создание
   primary требует platform-level proof contract.
4. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, passwdqc/ALT, codec, activation, D12
   coordinator/slot writer.
5. Не коммитить без явного запроса.
6. Инструментальная деталь: line-number-based вставки в
   `PamProviderManagedFlagExecutorTests.cpp` /
   `PamProviderManagedEntryJournalTests.cpp` повреждали файлы
   (восстановление через `git checkout`); использовать только
   text-anchor правки.
