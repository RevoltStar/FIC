# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `cfd588c` («Hardering-изменения для GRUB №2»).
- Рабочее дерево содержит незакоммиченный focused hardening follow-up к
  GRUB apply/rollback (см. Current task).

## Current task

- **GRUB hardening follow-up №3** — три изменения, все завершены в
  production-коде и тестах:
  1. **Убран последний check-then-unlink** —
     `GrubManagedConfig::restoreOriginal()` при компенсации
     initially-missing Debian drop-in больше НЕ делает
     `targetStateMatches(installed) → unlink(path)`. Вместо этого —
     атомарная CAS-запись (`expectedTargetState = installed`)
     канонического header-only FIC-owned артефакта
     (`GrubManagedConfig::canonicalEmptyContent()` =
     `"# Managed by FIC. Do not edit.\n\n"`, байт-в-байт совпадает с
     `canonicalContent()` пустого конфига) с post-write proof через
     `targetStateMatches`. Ключ политики после этого доказанно
     отсутствует → apply caller видит `Compensated`, `Prepared`
     discard'ится. `verifyOriginal()` для `!original_.exists` принимает
     canonical header-only контент либо физическое отсутствие (оба
     доказывают отсутствие ключа). Concurrent replacement при
     компенсации проваливает CAS → `ConcurrentDrift` →
     `Indeterminate`, внешнее состояние сохранено.
  2. **Post-rebuild proof apply (обе топологии, changed + idempotent)** —
     новый helper `proveExpectedGrubManagedValue()` + `enum class
     GrubManagedValueProof { Matches, Missing, Drift, Invalid }`
     (`GrubConfiguration.{h,cpp}`): свежая (fresh) инспекция текущего
     on-disk managed-источника через `inspectGrubManagedValue()`,
     никогда не reuse pre-rebuild snapshot'а. Вызывается после КАЖДОГО
     успешного rebuild: changed apply (Debian
     `ensureManagedGrubDropInValue`, ALT
     `GrubConfiguration::ensureManagedValue`) — proof != Matches →
     apply false, `sourceState = Indeterminate`, компенсация НЕ
     запускается, `Prepared` остаётся активным; idempotent apply —
     proof != Matches → apply false, `sourceState = Unchanged`,
     journal-запись не создаётся. Journal lifecycle matrix в `Grub.cpp`
     не менялась — новая семантика ложится на существующую.
  3. **Cleanup** — удалены dead `trimCopy` (`GrubManagedBlock.cpp`,
     canonical-strict parser не затронут) и `syncDirectory`
     (`GrubManagedConfig.cpp`, был нужен только удалённому unlink).
     Race-prone managed-unlink в GRUB subsystem больше нет.
- Тесты (`GrubPolicyTests.cpp`): `testManagedRebuildFailureCompensation`
  переписан под retention canonical empty для created-кейса + проверка
  `sourceState == Compensated`; created-drift кейс
  `testManagedConcurrentDriftCompensation` усилен заменой inode
  (rename) + проверкой `Indeterminate`.
- Тесты (`GrubRollbackJournalTests.cpp`, journal-level, deterministic
  rebuild-скрипты, мутирующие источник ВО ВРЕМЯ rebuild): T1
  `testDebianInitiallyMissingCompensationRetainsDropIn`, T2
  `testDebianInitiallyMissingCompensationConcurrentReplacement`, T3
  `testAltChangedApplyDriftDuringRebuild`, T4
  `testDebianChangedApplyDriftDuringRebuild` (valid + malformed), T5
  `testAltIdempotentDriftDuringRebuild`, T6
  `testDebianIdempotentDriftDuringRebuild`. T7 покрывается
  существующими lifecycle-тестами (Applied после нового post-rebuild
  proof).
- Docs: `docs/rollback.md` — новые инварианты «компенсация
  initially-missing Debian drop-in» и «post-rebuild proof apply».

## Accepted architecture / invariants

- FIC NEVER REMOVES A GRUB MANAGED PATH USING CHECK-THEN-UNLINK: при
  компенсации initially-missing drop-in остаётся canonical inert
  FIC-owned артефакт, физическое отсутствие не восстанавливается.
- Успешная пересборка grub.cfg НЕ доказывает managed-state compliance:
  `Prepared → Applied` коммитится только после свежего post-rebuild
  source proof; idempotent apply успешен только при доказанных
  pre-rebuild И post-rebuild состояниях.
- Ownership-release: rollback никогда не восстанавливает pre-FIC значение
  и не хранит snapshots; журнал доказывает только (key, appliedValue).
  Journal payload/schema, `MutationBackend::Grub`,
  `UndoRemoveGrubManagedSetting`, rollback enrollment — не менялись.
- Обязательная пересборка grub.cfg при каждом rollback, включая
  NothingToDo; всегда на провалидированных входах. Post-rebuild proof
  не заменяет и не отменяет `validateGrubRebuildInputs()`.
- Авторитетное описание инвариантов: `docs/rollback.md`, раздел
  «GRUB rollback (OSS/Grub)».
- Новые GRUB-политики никогда не становятся rollback-Supported
  автоматически — только через явное расширение whitelist в
  `RollbackExecutor.cpp` + journal integration.

## Completed

- Изменения 1–3 выше; тесты T1–T6 + обновлённые компенсационные тесты;
  обновлены `docs/rollback.md` и этот HANDOFF.

## Changed areas

- `fic/src/modules/oss/grub/{GrubConfiguration.h/cpp,
  GrubManagedConfig.h/cpp, GrubManagedBlock.cpp}`,
  `tests/fic/modules/oss/grub/{GrubPolicyTests.cpp,
  GrubRollbackJournalTests.cpp}`, `docs/rollback.md`, `docs/HANDOFF.md`.

## Validation

- Targeted: `grub_policy_tests` PASS, `grub_rollback_journal_tests`
  PASS, `mutation_journal_tests` PASS, `rollback_executor_tests` PASS,
  `ssh_apply_rollback_tests` PASS, `platform_profile_tests` PASS.
- Full build (`cmake --build build-grub -j4`, full tree): OK, 0 errors,
  0 warnings (в т.ч. никаких GRUB warnings).
- Full CTest: **97/97 — 100% passed, 0 failed**; 1 pre-existing skip
  (`command_hash_batch_tests`, not-run).
- `git diff --check`: clean.
- Code audit: `unlink(` / `removeOwnedManagedFile` /
  `artifactRemoved` / `syncDirectory` в GRUB scope отсутствуют (grep —
  только комментарии о retained drop-in); используемый парсером
  `trimCopy` в `GrubManagedConfig.cpp` оставлен, dead-копия в
  `GrubManagedBlock.cpp` удалена.
- Sanitizer build не выполнялся — не заявлять как выполненный.

## Remaining

- Закоммитить follow-up (9 изменённых файлов; конвенция сессий: коммит
  выполняется явно отдельным шагом). Вспомогательные build-каталоги
  `build-check` (устаревший, конфигурировался от `fic/`) и `build-grub`
  (актуальный, full tree) в git status не попадают (ignored).
