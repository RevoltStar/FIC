# FIC: передача контекста

## Current base

- Ветка `main`, HEAD — коммит «Реализация ROLLBACK для SSSD, KERBEROS»
  (`1b5be6b`); текущая задача — lifecycle/race-исправления SSSD/Kerberos
  rollback (см. ниже) — НЕ ЗАКОММИЧЕНА, рабочее дерево содержит изменения.

## Current task

- **SSSD/Kerberos rollback: lifecycle/race fixes** поверх уже
  реализованной journal-backed rollback-интеграции (apply →
  MutationJournal; disable → rollbackPolicyBeforeDisable → executor →
  typed undo). Архитектура не менялась (`MutationJournal +
  RollbackExecutor + typed UndoAction`, без `Policy::rollback()`;
  package/purge не тронуты).
  1. **SSSD — rollback = release + runtime reconciliation (один
     lifecycle)**: `undoSssdManagedSetting()` при уже отсутствующем FIC
     option НЕ возвращает мгновенный `NothingToDo` — обязательна runtime-
     реконсиляция (`reconcileSssdRuntime()` в `SssdRollback.{h,cpp}`:
     restart активного SSSD + verify). Неудачный restart → `RollbackFailed`
     (запись активна), retry disable повторяет реконсиляцию и завершает
     запись `RolledBack`.
  2. **SSSD — Prepared recovery**: active `Prepared` + доказанный AFTER +
     same-value apply → обязательная runtime-реконсиляция (даже при no-op
     persistent write), свежий повторный proof, тот же `MutationId`
     `Prepared → Applied`.
  3. **SSSD — proof-bound removal (анти-TOCTOU)**:
     `removeManagedSnippetFile()` в `SssdConfiguration.cpp` больше не
     `unlink(path)`: descriptor-proof (O_NOFOLLOW, identity+metadata+
     content) → атомарный rename в приватное имя → re-proof identity;
     иностранная замена восстанавливается byte-exact, removal fail closed.
     Test seam: `setManagedSnippetRemovalRaceHookForTests()`.
  4. **SSSD — компенсация удаления**: recreate только при доказанном
     ENOENT через exclusive create (O_EXCL); Unsafe/Unreadable/Changed —
     fail closed без записи (`classifyForCompensation()` /
     `exclusiveCreateOriginal()`).
  5. **Kerberos — no active record = no ownership**:
     `checkUnrecordedOwnership()` ветка KERBEROS всегда `NothingToDo`
     (foreign relation — не provenance FIC; foreign Kerberos файлы не
     парсятся).
  6. **Kerberos — Prepared recovery**: fresh full-graph AFTER proof →
     тот же `MutationId` `Prepared → Applied`; `Applied` same-value
     остаётся `Applied`.
  7. **Typed lifecycle results**: новый
     `executePreparedFileChangeDetailed()` (`Committed/Compensated/
     CompensationFailed`) в `PreparedFileChange.{h,cpp}`; SSSD/Kerberos
     apply больше не парсят `"recovery error"` из diagnostic strings.
  8. **Journal structural validation**: `section`/`option`/`relation`
     payload SSSD/Kerberos разбираются loader'ом через `find()` +
     `is_string()` — non-string JSON → fail closed без исключений
     (writer/loader parity сохранена).
  9. Regression-тесты: 10 новых сценариев в
     `IdentityConcretePoliciesTests.cpp` (retry runtime, SSSD/Kerberos
     Prepared recovery, race removal, 3 compensation-сценария, Kerberos
     no-record NothingToDo, retry после RolledBack, Applied same-value,
     RollbackFailed not promoted) + non-string malformed-тесты payload в
     `MutationJournalTests.cpp`.

## Accepted architecture / invariants

- SSSD: source ownership release и runtime реконсиляция — один rollback
  lifecycle; option absent сам по себе не означает завершённый rollback.
- SSSD/Kerberos: `Prepared → Applied` только после свежего
  AFTER/postcondition proof; `RollbackFailed` никогда не promoted
  автоматически (same-value apply fail closed).
- SSSD removal: удаляется только точно доказанное owned состояние;
  компенсация recreate — только доказанный ENOENT + exclusive create.
- Kerberos: без активной journal-записи FIC не владеет изменениями
  `ticket_lifetime`; foreign relation — никогда неявная provenance.
- Journal payload поля SSSD/Kerberos — структурный fail-closed parsing;
  lifecycle-решения — только typed results, не error strings.
- Авторитетное описание: `docs/rollback.md`, разделы «SSSD rollback»,
  «Prepared → Applied recovery» и «Kerberos rollback».

## Completed

- Lifecycle/race-исправления SSSD/Kerberos rollback (см. Current task) —
  код, тесты, docs.

## Changed areas

- `fic/src/rollback/{MutationJournal.cpp, RollbackExecutor.cpp}`;
- `fic/src/modules/identity_access/sssd/{SssdConfiguration.{h,cpp},
  SssdRollback.{h,cpp}}`;
- `fic/src/modules/identity_access/sssd/policies/
  SssdOfflineCredentialsExpirationPolicy.cpp`;
- `fic/src/modules/identity_access/kerberos/policies/
  KerberosTicketLifetimePolicy.cpp`;
- `fic/src/modules/identity_access/shared/configuration/
  PreparedFileChange.{h,cpp}`;
- `tests/fic/modules/identity_access/IdentityConcretePoliciesTests.cpp`;
- `tests/fic/rollback/MutationJournalTests.cpp`;
- `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- Targeted: `identity_concrete_policies_tests` (29 сценариев, вкл. 10
  новых), `mutation_journal_tests`, `rollback_executor_tests` — PASS.
- Full build (`build-fix`, `-DFIC_TARGET_PLATFORM=ubuntu-24.04`):
  0 errors / 0 warnings. Full CTest: 97/97 passed
  (`command_hash_batch_tests` — environment-dependent skip, как раньше).

## Remaining

- Санитизер-прогон не выполнялся (как и в предыдущих итерациях).
- Изменения текущей задачи НЕ закоммичены (на коммите `1b5be6b`).
- `git diff --check`: clean.
