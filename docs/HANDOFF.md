# FIC: передача контекста

## Current base

- Ветка `main`, HEAD — коммит «Hardering-изменения для GRUB №8» (этот
  коммит; предыдущий — `7474742` «Hardering-изменения для GRUB №7»).
- Рабочее дерево чистое; вспомогательные build-каталоги (`build-check`,
  `build-grub`, `build-sanitizers`, …) ignored.

## Current task

- **GRUB hardening follow-up №5** — provenance-safe repair lifecycle.
  Завершено. Главный инвариант: REPAIR OPERATION MUST NEVER DESTROY
  PRE-EXISTING ACTIVE PROVENANCE.
  1. **Fresh vs Reused Prepared** — новый GRUB-local transient repair
     context (`GrubPreparedRecordOrigin::{Fresh, ReusedActive}`,
     `GrubMutationPreparation`, `prepareGrubMutation()`,
     `restoreGrubMutationAfterNoopOrCompensation()` в `Grub.cpp`).
     Перед мутацией: если есть активная GRUB-запись (Applied/Prepared/
     RollbackFailed, payload `UndoRemoveGrubManagedSetting`, key совпадает,
     appliedValue == desired — иначе fail closed), она ВРЕМЕННО и durably
     переводится в `Prepared` (тот же MutationId, payload не переписывается),
     pre-repair status/error хранятся только в памяти операции. Вторая
     активная запись для того же resource никогда не создаётся.
  2. **Lifecycle matrix** — failure + `Unchanged`/`Compensated`:
     Fresh → discard; Reused → durable restore pre-repair status+error
     (restore только внутри доказанно завершённой операции). failure +
     `CompensatedPendingRebuild`/`Installed`/`Indeterminate` → Prepared
     остаётся. success + `Installed` → Applied (тот же id). success +
     `Unchanged` (defensive) → Fresh discard / Reused restore. Ошибки
     journal-операций — fail closed. Persistent journal никаких
     repair-полей не получает; крэш после → Prepared остаётся обычной
     активной записью (существующая recovery-модель).
  3. **Ineffective reconciliation без promotion** — `Ineffective`
     (ownership proven, EOF compliance unproven) после обязательной
     reconciliation-пересборки: same desired → активная запись
     сохраняется без перехода (Prepared/RollbackFailed НЕ promovятся в
     Applied, Applied не трогается), управление возвращается apply,
     который выполнит journaled relocation и закоммитит Applied только
     после свежего EOF proof; value change → old ownership release через
     `undoGrubManagedSetting()` БЕЗ промежуточного Applied, старая запись
     напрямую → `RolledBack`.
  4. **`GrubRollback.h`** — topology-specific wording: Debian last-key →
     canonical header-only `zzzz-fic.cfg` retained; ALT last-key →
     пустой FIC block удаляется целиком, сам `/etc/sysconfig/grub2` не
     удаляется никогда.
  5. Docs: `docs/rollback.md` — Fresh vs Reused матрица, transient
     context/crash semantics, Ineffective reconciliation без promotion.
  6. **№6 — GRUB journal identity consistency (fail closed)**:
     логическая идентичность GRUB mutation записи —
     (policy, backend, resource), а НЕ undo payload;
     `MutationRecord.resource == UndoRemoveGrubManagedSetting.key`
     обязательна. Loader отвергает (journal unusable):
     `resource != undo.key` (в любом направлении) и две одновременно
     active записи одного identity; historical resolved записи того же
     identity допустимы. `prepareMutation()` отказывается
     persist/refresh GRUB-запись с payload, не согласующимися с
     resource (idempotency-семантика для согласованных записей не
     изменена). `findReusableGrubRecord()` — typed exact-match
     (`None`/`Found`/`Invalid`): reusable record ищется ТОЛЬКО по exact
     (policy, backend=Grub, resource); payload валидируется против
     identity + desired value; >1 exact active record или malformed
     payload → fail closed БЕЗ fresh fallback (malformed exact-resource
     запись — не «no record»). №5 repair lifecycle не изменён.

## Accepted architecture / invariants

- FRESH PREPARED AND REUSED ACTIVE PROVENANCE ARE NOT THE SAME THING:
  failed/fully-compensated repair может discard только Fresh Prepared;
  Reused восстанавливает pre-repair логическое состояние.
- INEFFECTIVE PROVES OWNERSHIP, NOT COMPLIANCE; Prepared → Applied для
  ALT только после relocation + успешного rebuild + свежего EOF proof.
- Same MutationId безопасно переживает Applied → Prepared → Applied
  repair; параллельные активные GRUB-записи одного resource запрещены
  (MutationJournal invariant сохранён).
- ALT OWNERSHIP vs COMPLIANCE, CompensatedPendingRebuild,
  canonical Debian drop-in, no check-then-unlink, single-snapshot CAS,
  ownership-release rollback — без изменений (follow-up №4).
- Авторитетное описание: `docs/rollback.md`, раздел
  «GRUB rollback (OSS/Grub)».

## Completed

- Пункты 1–5 выше. Регрессионные тесты T1–T8 в
  `tests/fic/modules/oss/grub/GrubRollbackJournalTests.cpp`:
  T1 `testExistingAppliedSameValueRepairSucceeds` (Applied → Prepared →
  Applied, тот же id, ровно одна запись, foreign tail сохранён),
  T2 `testExistingAppliedRelocationCasFailureRestoresProvenance`
  (CAS-race → restore Applied, внешние байты byte-exact),
  T3 `testExistingAppliedFullCompensationRestoresApplied` (главный
  regression: full compensation восстанавливает Applied вместо
  discard; stateful rebuild-скрипт: reconciliation ok, primary fail,
  compensating ok), T4 `testExistingPreparedSurvivesCompensatedRepair`,
  T5 `testExistingRollbackFailedSurvivesCompensatedRepair` (с
  восстановлением previous error), T6
  `testExistingAppliedPendingRepairStaysPrepared` (PendingRebuild держит
  Prepared; retry → одна Applied), T7
  `testIneffectivePreparedNotPromotedBeforeRelocation` (перед
  relocation write статус == Prepared), T8
  `testIneffectiveValueChangeReleasesOwnershipWithoutPromotion`
  (old → RolledBack без промежуточного Applied; одна Applied для нового
  значения). Все существующие тесты №4 и раньше остались зелёными.
- №6: loader-тесты в `MutationJournalTests.cpp` — T1/T2
  `testGrubResourcePayloadMismatchFailsClosed` (resource/undo.key
  mismatch в обоих направлениях → load fail closed),
  `testDuplicateActiveLogicalIdentityFailsClosed` (Applied+Prepared
  одного identity → fail closed), `testResolvedHistoryWithActiveRecordLoads`
  (RolledBack+Applied одного identity → load успешен, история
  сохранена). GRUB-level: `testWrongResourceRecordIsNotReusedByPayloadKey`
  в `GrubRollbackJournalTests.cpp` (запись чужого resource не
  переиспользуется по payload key; fresh fallback; payload чужой записи
  не переписывается). После №7 уточнение: malformed GRUB payload
  (кроме пустого appliedValue) через public API невоспроизводим —
  loader + prepareMutation его отвергают; helper `Invalid`-ветка
  покрывается loader-тестами как defense-in-depth.
- №7 (P1 fix): пустой `appliedValue` GRUB undo payload — ВАЛИДНОЕ
  состояние (`grub_cmdline_linux=""`): ранее `prepareMutation()`
  допускал запись с `appliedValue == ""`, но `deserializeUndoAction()`
  отвергал пустой `applied_value`, ломая journal после такого apply.
  Общая `validateGrubUndoPayload()` в `MutationJournal.cpp` используется
  на write (`prepareMutation`) и read (`deserializeUndoAction`) путях —
  writer не может создать запись, которую loader отвергнет. Правила:
  key непуст + `isGrubManagedKey`, appliedValue (в т.ч. пустой) без
  CR/LF/NUL; resource == undo.key — без изменений. Тесты:
  `testGrubEmptyAppliedValueRoundTrip` (persist → reload),
  `testEmptyPolicyValueAppliedSurvivesRestartLikeReload`
  (apply `""` → Applied → restart-like reload → idempotent re-apply);
  кейс «empty applied value» удалён из malformed-теста loader'а.
- №8: структурный parsing `applied_value` GRUB undo payload в
  `deserializeUndoAction()`: поле ОБЯЗАНО присутствовать и быть JSON
  string (`""` валидно); missing / non-string / null `applied_value` →
  load fail closed с диагностикой (раньше missing молча превращался в
  `""`, а non-string мог выйти непойманным JSON type error —
  deserializeRecord вызывается вне try/catch).
  `validateGrubUndoPayload()` осталась semantic-validator'ом (key +
  managed-key whitelist + CR/LF/NUL). Тесты: missing / non-string /
  null applied_value → fail closed в
  `testGrubUndoMalformedPayloadsFailClosed`;
  `testGrubEmptyAppliedValueLoadsDirectly` (raw document с
  `applied_value: ""` → load succeeds).
  `testEmptyPolicyValueAppliedSurvivesRestartLikeReload` усилен:
  после первого apply singleton journal закрывается
  (`setOverridePath`) и переоткрывается через production startup path
  (`tryGet` → `initializeOrLoad`); Applied-запись с пустым
  appliedValue переживает daemon-style reopen как единственная
  активная, затем idempotent повторный apply через переоткрытый
  singleton.

## Changed areas

- `fic/src/modules/oss/grub/{Grub.cpp, GrubRollback.h}`,
  `fic/src/rollback/MutationJournal.cpp`,
  `tests/fic/modules/oss/grub/GrubRollbackJournalTests.cpp`,
  `tests/fic/rollback/MutationJournalTests.cpp`,
  `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- Targeted (№7/№8): `mutation_journal_tests`,
  `grub_rollback_journal_tests`, `grub_policy_tests`,
  `rollback_executor_tests` — все PASS, включая
  `testGrubEmptyAppliedValueRoundTrip`,
  `testGrubEmptyAppliedValueLoadsDirectly` и
  `testEmptyPolicyValueAppliedSurvivesRestartLikeReload`
  (production daemon-style reopen через `initializeOrLoad`).
- Full build + full CTest: 100% passed, 0 failed (97 tests; 1
  environment-dependent skip `command_hash_batch_tests`, как и в №6).
- `git diff --check`: clean.
- Sanitizer build не выполнялся — не заявлять как выполненный.

## Remaining

- Опционально: sanitizer-прогон при появлении соответствующего профиля.