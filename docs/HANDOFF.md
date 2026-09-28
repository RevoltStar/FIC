# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `e011859` (Step 7A + follow-up №1 + follow-up №2
  закоммичены).
- Рабочее дерево содержит **Step 7B** (base commit = `e011859`, изменения
  НЕ закоммичены).
- Коммит НЕ делать без явного запроса пользователя.

## Current task

**Step 7B (выполнен, не закоммичен):** перевод трёх scalar-политик
`pam_faillock` (`deny` = failed_authentication_attempts, `fail_interval` =
failed_authentication_counting_period, `unlock_time` =
failed_authentication_unlock_time) на journal-backed managed-entry
исполнение поверх Step 7A primitives. Полный crash-recovery matrix,
container provenance lifecycle, routing + production wiring, unit tests.
7C/7D/7E/7F НЕ трогали; disable/release wiring НЕ трогали.

### Что реализовано (Step 7B)

Новые файлы:

- `fic/src/modules/identity_access/pam/PamProviderManagedEntryExecutor.h/.cpp` —
  reusable executor одной logical transaction managed entry:
  - routing-функции `usesPamProviderManagedEntry()` (только PamFaillock +
    ProviderConfigFile + Assignment syntax + ровно 3 scalar feature; всё
    остальное — legacy path) и `pamProviderAbsentContainerDecision()`
    (FailClosed для `ReplacesNativeTopology`; на сегодня НИ ОДНА платформа
    не доказывает CreateFicOwned — тесты прокидывают CreateFicOwned явно);
  - `PamProviderManagedEntryExecutor::apply(request, journal, semantic,
    outcome, error)` — caller держит `configurationMutex`, executor без
    локальных mutex, без whole-file snapshot rollback;
  - journal identity: entry = PolicyRef `IDENTITY_ACCESS/PAM/<policyName>`
    + `UndoRemovePamProviderManagedEntry`; container =
    `IDENTITY_ACCESS/PAM_CONTAINER/<providerName>` +
    `UndoOwnPamProviderContainer`;
  - recovery ВСЕГДА через Step 7A classifier
    (`classifyPamProviderJournalBinding`), дубликаты семантики запрещены;
  - refresh = `prepareMutation(previous=old appliedBody)` с assertion того
    же record id; typed fail-closed ошибки PreparedConflict /
    AppliedMissing / AppliedDrifted / unprovable RollbackFailed; displaced
    owned block переносится ТОЛЬКО после exact ownership proof; no-op
    требует полной proof chain (value + id + placement + semantic);
  - container provenance НЕ фабрикуется для pre-existing файлов; Prepared
    container Completed только после proven FIC entry ownership; absent
    container при FailClosed отказывается ДО подготовки journal records.
- `tests/fic/modules/identity_access/pam/PamProviderManagedEntryExecutorTests.cpp`
  — 16 кейсов: routing decision, absent-container FailClosed (без journal
  records), FIC-created container lifecycle, proven no-op, reuse Applied
  provenance второй политикой, crash matrix (PreparedFreshAbsent /
  PreparedFreshTargetPresent / PreparedUpdatePreviousPresent /
  PreparedUpdateTargetPresent / PreparedConflict / AppliedMissing /
  AppliedDrifted), update lifecycle same-id, foreign mutation id (9)
  conflict, три политики в одном блоке + byte-exact foreign bytes +
  стабильные neighbor id, restart recovery через свежий объект журнала.

Изменённые:

- `fic/src/modules/identity_access/pam/PamOptionPolicy.{h,cpp}` — routing в
  `applyPam()` после вычисления `nativeExpectedValue`:
  `usesPamProviderManagedEntry()` → `applyManagedProviderEntry()`
  (structural preflight через существующий verifier pipeline → MANDATORY
  usable journal через `DaemonMutationJournal::tryGet` (fail closed, БЕЗ
  legacy-writer fallback) → executor с semantic postcondition =
  существующий `verifyPostMutationPamState`; НЕ используется shortcut
  `hasExpectedState`).
- `tests/CMakeLists.txt` — новый таргет
  `pam_provider_managed_entry_executor_tests` + closure-исходники executor
  добавлены в 3 существующих таргета, компилирующих `PamOptionPolicy.cpp`.

### Invariants (не ослаблять в 7C–7F)

- Executor никогда не пишет физически без Prepared journal provenance.
- Prepared provenance никогда не отбрасывается: любая ошибка оставляет
  recoverable состояние; recovery всегда через classifier.
- Container record независим от entry record (см. Step 7A follow-up №2:
  ≤ 1 active `own_pam_provider_container` на configPath).
- Absent-container решение — typed на caller'е; `ReplacesNativeTopology`
  + отсутствие primary = отказ (vendor fallback непроверяем).

## Validation (фактически выполнено)

- `cmake --build build-check --target fic` — PASS, warnings нет.
- `ctest -R pam_provider_managed` → **4/4 PASS** (включая новый
  `pam_provider_managed_entry_executor_tests`).
- Полный build `build-check` — PASS (все таргеты, включая тесты,
  компилирующие `PamOptionPolicy.cpp`).
- Полный CTest: **111/111 PASS** (1 skip: `command_hash_batch_tests`,
  окружение).
- `git diff --check` — чисто.

## Remaining (Step 7C+)

1. 7C: pwquality на этот же executor (routing уже параметризован
   provider'ом; absent-container решение для pwquality — тоже
   `ReplacesNativeTopology` → FailClosed).
2. 7D: pwhistory BOF placement; 7E: suppress/wrapper set-only false;
   7F: rollback executor wiring + package release + unlink FIC-created
   container.
3. **Step 7F contract — snapshot-bound unlink (обязательно):**
   `pamProviderContainerReleaseDecision() == RemovableFicOwned` — только
   логическая eligibility, НЕ proof, что текущий filesystem object можно
   unlink. Proof → заменa файла attacker'ом/admin'ом → plain
   `std::filesystem::remove(path)` удаляет replacement — ЗАПРЕЩЕНО.
   Release executor обязан: trusted capture точного текущего snapshot
   контейнера → strict parse → доказать exact final FIC-owned entry/block
   ownership → доказать durable own_pam_provider_container provenance →
   доказать zero foreign bytes после удаления → убедиться target ==
   captured state → conditional delete exact target (иначе fail stale) →
   fsync parent directory → только затем resolve container provenance
   journal record. Conditional-delete primitive в проекте пока НЕТ —
   реализовать в 7F.
4. Прод-apply трёх faillock политик на absent primary отказывает
   (FailClosed): прод-создание `/etc/security/faillock.conf` потребует
   platform-level proof contract — отдельное архитектурное решение.
5. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, Debian 12 pwhistory ModuleArguments.
6. Не коммитить без явного запроса.
