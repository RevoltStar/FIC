# FIC: передача контекста

## Current base

- Ветка `main`, HEAD — коммит «Hardering-изменения для GRUB №5» (этот
  коммит; предыдущий — `c9aedad` «Hardering-изменения для GRUB №4»).
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

## Changed areas

- `fic/src/modules/oss/grub/{Grub.cpp, GrubRollback.h}`,
  `tests/fic/modules/oss/grub/GrubRollbackJournalTests.cpp`,
  `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- Targeted: `grub_policy_tests`, `grub_rollback_journal_tests`,
  `mutation_journal_tests`, `rollback_executor_tests`,
  `ssh_apply_rollback_tests`, `platform_profile_tests` — все PASS.
- Full build (`cmake --build build-grub -j4`, full tree): OK, 0 errors,
  0 warnings.
- Full CTest: **97/97 — 100% passed, 0 failed**.
- `git diff --check`: clean.
- Sanitizer build не выполнялся — не заявлять как выполненный.

## Remaining

- Опционально: sanitizer-прогон при появлении соответствующего профиля.