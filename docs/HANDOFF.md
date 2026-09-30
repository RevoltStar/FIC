# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `b61e616` («Приступаем к Step7E», родитель
  `d2327b5`). Поверх HEAD — незакоммиченный **follow-up к Step 7E**
  (P1/P2-фиксы, см. Current task). Коммит НЕ делать без явного запроса.

## Current task

**Follow-up к Step 7E (выполнен, не закоммичен):**
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
  (namespace = configPath). Prepared = target ∪ previous; Applied/
  RollbackFailed = target; resolved — never authority. Инвариант
  соблюдается и на load, и на write (parity).

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
- Follow-up (эта сессия): P1 identity/ownership split + fail-closed
  fresh; P2 authority model load+write; парсер-фикс публикации
  suppressions вне блока; include cleanup.

### Changed areas

- `fic/src/modules/identity_access/pam/PamProviderManagedBlock.{h,cpp}`
  (парсер-фикс publish-suppressions; include cleanup)
- `fic/src/modules/identity_access/pam/PamProviderManagedFlagExecutor.cpp`
  (P1: FlagPhysicalInspection/inspect/applyFreshFlag)
- `fic/src/rollback/MutationJournal.cpp` (P2: activeFlagAuthority
  load-side; write-side parity в prepareMutation)
- `tests/fic/modules/identity_access/pam/
  PamProviderManagedFlagExecutorTests.cpp` (+3 теста: orphan wrapper
  refuse для desired=false/true, foreign-mutation-id fail-closed для
  обоих desired; helpers `forgeWrapperLine`/`writeOrphanWrapperState`)
- `tests/fic/rollback/PamProviderManagedEntryJournalTests.cpp`
  (+`testFlagSuppressionAuthorityInvariants`: load-side cases A–D,
  Applied-previous-not-authority, cross-file OK; write-side parity)
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
