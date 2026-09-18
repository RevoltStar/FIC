# FIC: передача контекста

## Current base

- Ветка `main`, HEAD — коммит «Hardering-изменения для GRUB №4» (этот
  коммит; предыдущий — `3d04f57` «Hardering-изменения для GRUB №3»).
- Рабочее дерево чистое; вспомогательные build-каталоги (`build-check`,
  `build-grub`) ignored.

## Current task

- **GRUB hardening follow-up №4** — ALT EOF placement как часть
  compliance proof + incomplete-compensation provenance. Завершено.
  1. **ALT ownership vs compliance** — parser (`GrubManagedBlockView`)
     сообщает типизированное размещение `GrubManagedBlockPlacement`
     (`Absent`/`AtEof`/`NotAtEof`): `AtEof` = нет foreign физических
     строк после END-маркера. Валидный блок с foreign tail остаётся
     parse-valid (ownership proof), но НЕ compliance. Инспекция несёт
     `GrubValueObservation::managedLayerEffective` (Debian — всегда
     true); typed proof `GrubManagedValueProof::Ineffective`;
     journal-классификация `GrubManagedJournalState::Ineffective`;
     единый predicate `grubManagedValueCompliant()`. ALT same-value блок
     NotAtEof → `needsChange = true` → Prepared ДО relocation →
     существующий rewrite-mechanism (`setGrubManagedBlockValue`)
     сохраняет foreign байты и ставит блок в EOF → post-rebuild proof
     требует EOF. Rollback ownership-release EOF НЕ требует (валидный
     non-EOF блок удаляем, foreign tail byte-exact). `Ineffective`
     journal-запись разрешается по ownership как `After`; effective
     placement восстанавливает следующий journaled apply.
  2. **CompensatedPendingRebuild** — новый
     `GrubSourceMutationState::CompensatedPendingRebuild`: source
     восстановлен, но компенсирующая пересборка провалилась (или не
     запущена из-за провала `validateGrubRebuildInputs`) → компенсация
     НЕПОЛНА, Prepared остаётся активным (ALT
     `compensateAfterRebuildFailure` + обе Debian compensation-ветки
     `ensureManagedGrubDropInValue`, включая initially-missing →
     canonical header-only). `Compensated` теперь означает: source
     восстановлен И компенсирующая пересборка успешна → Prepared
     discard. Recovery path без изменений: classify BEFORE →
     обязательная пересборка → discard stale Prepared → fresh apply.
  3. Docs: `docs/rollback.md` — раздел GRUB дополнен инвариантами ALT
     ownership/compliance, needsChange/relocation, lifecycle matrix с
     `CompensatedPendingRebuild`, post-rebuild EOF proof.

## Accepted architecture / invariants

- ALT OWNERSHIP И ALT COMPLIANCE — РАЗНЫЕ доказательства: ownership =
  валидный блок с записанным key/value; compliance = то же + блок в EOF
  (shell last assignment wins). Валидный блок с foreign tail — не
  malformed (иначе apply не смог бы безопасно relocat'ить свой блок).
- Prepared → Applied требует: expected value + valid managed source +
  EOF placement (ALT) + успешный rebuild + свежий post-rebuild proof.
- Same-value relocation блока из середины файла в EOF — РЕАЛЬНАЯ
  журналируемая мутация; невидимых source-мутаций нет.
- Source restore без успешной компенсирующей пересборки — не полная
  компенсация и не discard provenance. Повторно возвращать source в
  Applied-состояние после неудачной компенсирующей пересборки НЕ
  требуется — recovery завершает reconciliation.
- FIC NEVER REMOVES A GRUB MANAGED PATH USING CHECK-THEN-UNLINK;
  canonical header-only Debian drop-in retained; single-snapshot CAS;
  ownership-release без previous-value restore и snapshots; validated
  rebuild inputs перед каждой пересборкой; обязательная пересборка при
  каждом rollback, включая NothingToDo.
- Авторитетное описание: `docs/rollback.md`, раздел
  «GRUB rollback (OSS/Grub)».

## Completed

- Пункты 1–3 выше. Тесты: T1
  `testAltSameValueNotEofRelocation` (Prepared-before-relocation через
  pre-write seam), T2b `testAltChangedForeignTailDuringRebuild`, T3b
  `testAltIdempotentForeignTailDuringRebuild`, T4
  `testAltRollbackNonEofOwnedBlock`, T5+T7
  `testDebianDoubleRebuildFailureKeepsPrepared` (double failure →
  Prepared активен → retry recovery → ровно одна Applied), T6+T8
  `testAltDoubleRebuildFailureKeepsPrepared`, T9
  `testDebianInitiallyMissingCompensationPendingRebuild` (canonical
  empty компенсация + failed compensating rebuild → Prepared → recovery
  OK). Backend-level: `testAltDoubleRebuildFailurePendingRebuild`,
  `testAltPlacementComplianceSemantics` (inspect/proof/classify),
  parser placement-ассерты, `testManagedRebuildFailureCompensation`
  + case `created-double-failure`. Обновлён
  `testDebianInitiallyMissingCompensationRetainsDropIn`: failed
  compensating rebuild теперь держит Prepared (старое expectation
  discard закрепляло неполную компенсацию).

## Changed areas

- `fic/src/modules/oss/grub/{GrubConfiguration.h/cpp, Grub.cpp,
  GrubManagedBlock.h/cpp, GrubRollback.h}`,
  `tests/fic/modules/oss/grub/{GrubPolicyTests.cpp,
  GrubRollbackJournalTests.cpp}`, `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- Targeted: `grub_policy_tests` PASS, `grub_rollback_journal_tests`
  PASS, `mutation_journal_tests` PASS, `rollback_executor_tests` PASS,
  `ssh_apply_rollback_tests` PASS, `platform_profile_tests` PASS.
- Full build (`cmake --build build-grub -j4`, full tree): OK, 0 errors,
  0 warnings.
- Full CTest: **97/97 — 100% passed, 0 failed**; 1 pre-existing skip
  (`command_hash_batch_tests`, not-run).
- `git diff --check`: clean.
- Sanitizer build не выполнялся — не заявлять как выполненный.

## Remaining

- Опционально: sanitizer-прогон при появлении соответствующего профиля.
