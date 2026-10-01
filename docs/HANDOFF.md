# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `040f2e1...` ("Follow-up к последнему коммиту").
  Поверх HEAD — **незакоммиченный final security follow-up к Шагу 7F**
  (4 дефекта PAM provider rollback / package release). Коммит НЕ делать
  без явного запроса.

## Current task

**Final security follow-up (4 дефекта) — реализация и валидация
завершены, не закоммичено.** Base before this follow-up: `040f2e1…`
(чистое дерево). Шаги 7A–7F и их семантика ownership/journal не
менялись — только ужесточение proof-путей:

- **(P1) Current-platform proof для `UndoOwnPamProviderContainer`.**
  Новый SSOT-хелпер `pamProviderContainerRollbackRouteForPayload()`
  (`PamProviderRollback.h/.cpp`): ProviderConfigFile capability с
  lexically-exact configPath + provider name match + принадлежность
  managed-provider domain через `pamProviderManagedEntryPlacement(...).
  has_value()` (derived от typed routing/catalog, БЕЗ distro switch).
  Применён в runtime (`undoOwnPamProviderContainerUnlocked` — Conflict
  ДО любого read/mutation journal path) и в package Stage A (container
  coherence — fail closed перед `readForMutation`).
- **(P2) Точный orphan coverage.** `preflightPhysicalState` в
  `PamProviderPackageRelease.cpp`: покрытие физического FIC объекта =
  ровно одна активная запись с точной identity (path+provider+policy+
  managedKey), доказанная через `classifyPamProviderJournalBinding`
  (entry) или flag release proof (flag-owned entry); ambiguity → fail
  closed. Wrapper покрыт только если его suppression id ∈ АКТИВНОЙ
  authority ровно одной flag записи — единая модель вынесена в shared
  `fic::rollback::activePamFlagSuppressionAuthority()`
  (`MutationJournal.h/.cpp`; Prepared: suppressionIds ∪
  previousSuppressionIds; Applied/RollbackFailed: suppressionIds;
  resolved: none). Слабой модели (path, policy) больше нет.
- **(P2) Typed payload route: policy ↔ feature ↔ key ↔ syntax.**
  `pamProviderRollbackRouteForPayload()` расширен параметрами
  `policyName` + `expectedSyntax` (Assignment для entry undo, Flag для
  flag undo): доказывает `pamProviderManagedFeaturePolicyName(
  binding.feature) == policyName` и `binding.syntax == expectedSyntax`.
  Используется и runtime rollback, и package Stage A per-record proof.
- **(P2) Final sweep без stale/resolved записей.** `run(Release)`:
  destructive sweep контейнеров идёт по id записей, активных на момент
  старта release, но каждая запись перечитывается из ТЕКУЩЕГО journal;
  уже resolved (policy-release-deletes-container) — только report без
  второго lifecycle pass; исчезнувшая запись — integrity error.
  Дополнительно defense-in-depth refusal в
  `undoOwnPamProviderContainerUnlocked`: переданная копия записи обязана
  совпадать с текущей активной записью journal (stale/Detached/
  RolledBack → Conflict, никакого второго lifecycle owner).

## Accepted architecture / invariants

- Все прежние инварианты Шага 7F (ownership proof, Stage A/B
  согласованность, conditional delete hardening, managed-provider lock,
  SSOT provider primaries без `configTopology.has_value()`) — без
  изменений, не пересматривать.
- Container provenance proof — часть того же typed SSOT; второго
  whitelist/distro switch не вводить.
- `activePamFlagSuppressionAuthority` — единственная модель authority
  suppression wrapper'ов; не дублировать в preflight/executors.

## Completed

- Все 4 фикса выше + регрессии: `PamProviderRollbackTests` (+6: wrong
  path / wrong provider container proof, Detached no-second-lifecycle,
  flag↔assignment masquerade ×2, wrong policy for correct key),
  `PamProviderPackageReleaseTests` (+5: wrong-key same-policy orphan
  entry, wrong mutation id, wrong-key orphan wrapper, Prepared
  previous-wrapper authority, independent active container processed).
- Негативный контроль на base `040f2e1` (отдельный worktree, новые
  тест-файлы поверх base-кода): 7 из 11 новых регрессий падают на base
  (дефекты доказаны); wrong-mutation-id, prepared-previous-authority и
  independent-container проходят на обеих версиях (guards, а не
  regressions).

## Changed areas

- `fic/src/modules/identity_access/pam/PamProviderRollback.{h,cpp}`,
  `fic/src/modules/identity_access/pam/PamProviderPackageRelease.cpp`,
  `fic/src/rollback/MutationJournal.{h,cpp}`.
- `tests/fic/modules/identity_access/pam/{PamProviderRollbackTests,
  PamProviderPackageReleaseTests}.cpp` (регистрация в main() каждого
  файла; CTest-цели уже существовали, `tests/CMakeLists.txt` не менялся).

## Validation (фактически выполнено)

- Полный build `build-check` (ubuntu-24.04) — 0 errors.
- Полный CTest — **115/115 PASS** (1 skip: `command_hash_batch_tests`,
  окружение).
- `python3 tests/integration/packaging/PamPackagingChecks.py $PWD` — PASS.
- `git diff --check` — чисто.
- **Real-distro gates: все 5 PASS** — `pam_provider_rollback_gate.sh`
  на debian-12, debian-13, ubuntu-24.04, ubuntu-26.04 (G1–G10);
  `pam_provider_rollback_gate_alt.sh` на altlinux-11 (A1–A9).

## Remaining

1. Коммит НЕ делать без явного запроса.
2. Optional 4 mutation-checks (`pam_prerm_release_gate.sh`: history-
   initial / quality-history / foreign-quality-history /
   foreign-added-during-fic) НЕ завершены: (а) apt-get update/install
   в контейнере стал нестабилен (зеркала sandbox); (б) сценарии 1–2
   упали на C2 topology bootstrap ПРИ УСТАНОВКЕ СТАРЫХ prebuilt debs из
   `dist/` (built 2025-09-21, до всех изменений этого follow-up) —
   отношение к изменениям исключено: gate ставит пакеты из `dist/`, а
   не из исходников. Перед повтором: пересобрать debs; запускать с
   `-e http_proxy= -e https_proxy=` — в отличие от rollback gate,
   prerm-скрипт НЕ сбрасывает хостовый loopback proxy.
3. Не трогали (вне scope): C2 topology, PamOptionFile semantics,
   Step 6 option reconciliation, codec, activation, D12 coordinator.

## Следующему агенту

- `pamProviderRollbackRouteForPayload` теперь имеет 8 параметров; все
  callers обновлены (только `PamProviderPackageRelease.cpp` + внутренний
  runtime path в `PamProviderRollback.cpp`).
- Container sweep в `run(Release)` работает по `containerIds`
  (active-at-start) + перечитывание текущего состояния по id; report
  buckets (deleted/detached/retained) заполняются и для уже-resolved
  записей (policy-release-deletes-container).
- Прежние «Follow-up добавления к Шагу 7F» (driver lifecycle, SSOT
  policy identity, сериализация enabled-флага, driver bootstrap rm -rf)
  остаются в силе как знания о gate-инфраструктуре.
