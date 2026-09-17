# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `728262c` (hardening follow-up к
  platform-baseline rollback: object type safety + fd lifetime).
- Рабочее дерево содержит незакоммиченный journal-lifecycle follow-up к
  `728262c` (см. Current task).

## Current task

- **Journal lifecycle follow-up к `728262c`** (незакоммичено):
  `ModeAndOwner::applyWithBaselineJournalProvenance()` больше не оставляет
  ложный Prepared-record после failed apply без мутации. Матрица:
  success+changed → commit; success+unchanged → discard; failure+changed →
  Prepared остаётся (partial provenance); failure+unchanged → discard, return
  false. Ошибка discard/commit — fail closed (return false, ERROR diagnostic).
  Контракт apply→enforced / disable→baseline НЕ менялся.

## Accepted architecture / invariants

- **Модель platform profile** (`PlatformProfile.h`): `FileMetadata{owner,
  group, mode_t permissions}`; `FileAccessRule{path, enforced, baseline,
  allowedFinalSymlinkTargets, providerManagedFinalSymlinkTargets}`;
  `ProviderManagedFileTarget{path, provider, enforced, baseline}` (все
  текущие targets: enforced == baseline — штатное provider state);
  `TcbCredentialFileRule{name, permissions, baselinePermissions, required}`;
  `TcbCredentialStorageConfig` получил `rootBaselinePermissions` и
  `entryDirectoryBaselinePermissions`. Baseline — platform-defined штатное
  состояние дистрибутива, НЕ pre-FIC snapshot; имена original/previous/old
  запрещены.
- **Platform-baseline rollback** (docs/rollback.md, раздел «Platform-baseline
  rollback (DAC hardening)» — authoritative): apply → enforced; disable →
  baseline. Journal payload `UndoApplyDacPlatformBaseline{policyName}`
  (backend `Dac`, journal action `apply_dac_platform_baseline`) несёт ТОЛЬКО
  policy identity; pre-FIC metadata не хранятся. Источник истины baseline —
  `PlatformProfile` (через `RollbackExecutorDeps::dacOptions`), никаких
  distro-switch в rollback-коде.
- **Provenance в apply**: обе DAC-политики вызывают
  `ModeAndOwner::applyWithBaselineJournalProvenance()` — Prepared-запись ДО
  мутации (fail closed при недоступном journal), далее матрица по
  `ModeAndOwner::lastApplyChangedSystemState()`: success+changed → commit;
  success+unchanged → discard; failure+changed → Prepared остаётся активным
  (partial mutation provenance); failure+unchanged → discard (без мутации
  provenance не существует). Ошибка discard при unchanged тоже fail closed
  (return false + ERROR), ложный активный Prepared недопустим.
  `lastApplyFixedCount_` устанавливается на ОБОИХ выходах `ModeAndOwner::apply()`
  (успех и failure) — changed-флаг корректен при partial failure. ВАЖНО:
  внутри wrapper'а вызов `this->ModeAndOwner::apply()` НЕВИРТУАЛЬНЫЙ —
  виртуальный вызов даёт бесконечную рекурсию apply↔wrapper.
- **Legacy provenance без journal**: ownership доказывается наличием
  enforced-состояния (владение enforced + mode ⊆ enforced) при отсутствии
  объектов в чужом состоянии: доказано → rollback к baseline выполняется;
  всё в baseline → NothingToDo; чужое/небезопасное → Unsupported (disable
  запрещён). `dacLegacyBaselineRollback` в RollbackExecutor.cpp.
- **Fail-closed object safety** (apply и rollback): `FileStats::openPolicyPath`
  (symlink allowlists + provider targets), тип объекта, `fstat`-postcondition.
  Небезопасный объект → Conflict до мутации. Missing → Ignore, объекты не
  создаются. Partial failure → `RollbackStatus::Partial`, journal остаётся
  активным, повторный disable повторяет rollback (baseline→baseline no-op
  идемпотентен).
- **Enrollment**: DAC/Mode_and_Owner whitelist — только эти две политики
  Supported; `custom_mode_and_owner` и прочие Mode_and_Owner — NotEnrolled
  (legacy disable). `custom_mode_and_owner` не тронут (4-arg
  `addExpectedRule` overload: enforced == baseline).
- **GUI/UI**: `FileAccessRulesPolicyTypeValue::getPolicyRestrictionInfo`
  показывает только enforced; baseline — implementation detail.
- **SSH ownership-release** и все остальные rollback backends не изменены.

## Completed

- Модель: `FileMetadata` + enforced/baseline в `FileAccessRule`,
  `ProviderManagedFileTarget`, TCB-структурах; валидация
  `PlatformCompatibility` (non-empty owner/group + валидный mode для
  enforced и baseline, provider targets, TCB baseline-поля).
- Профили Debian 12/13, Ubuntu 24.04/26.04, ALT p11 переведены на
  enforced/baseline. Ключевые значения: commands enforced 0750 / baseline
  0755 root:root; `/etc/crontab` enforced 0600 / baseline 0644
  (Debian/Ubuntu, проверено по пакетам `cron-daemon-common` 3.0pl1-162 и
  -197 из deb.debian.org); `/etc/shadow` Debian/Ubuntu root:shadow 0640
  (shadowconfig), ALT root:root 0400; sudoers 0440 (postinst sudo);
  `/usr/sbin/ip`→`/usr/bin/ip` и `/usr/bin/df`→`/usr/bin/gnudf`
  symlink-исключения сохранены. ALT `/etc/crontab` baseline оставлен 0600
  (RPM-verification заблокирована: packages.altlinux.org/rdb.altlinux.org за
  Anubis; в profile комментарий — перепроверить `rpm -q --dump cron`).
- Новый backend `DacBaselineRollback.{h,cpp}`: `undoDacBaselineMutation`
  (static files + provider targets + TCB через
  `rollbackTcbTreeToBaseline`), `checkDacBaselineOwnership` (legacy).
  TCB-сборка рефакторена в общие `collectTcbTree`/`tcbTopologyUnchanged`
  (DAC_blocking...cpp), apply и rollback используют одну collection.
- `MutationBackend::Dac` + `UndoApplyDacPlatformBaseline` + journal
  serialize/deserialize; `RollbackExecutor`: dispatch, enrollment whitelist,
  legacy-path, `deps.dacOptions` в `productionRollbackDeps`.
- Тесты: `ModeAndOwnerTests` +6 (A–H: apply enforced, rollback baseline,
  0777→0750→0755, admin-drift, idempotent, missing, symlink fail-closed,
  provider target) + journal override; `RollbackExecutorTests` +6 DAC
  (baseline transition + journal resolve, idempotent повтор, legacy
  provenance ×3, blocking 0600→0644); `PlatformProfileTests` обновлены под
  enforced/baseline + provider/TCB baseline-проверки; `static_checks.py`
  обновлён под новый текст профилей.
- `docs/rollback.md`: раздел «Platform-baseline rollback (DAC hardening)»,
  Undo action bullet, enrollment, «Расширение».
- Follow-up (`65165ef`): static type check apply+rollback, `UniqueFd` в
  `rollbackTcbTreeToBaseline`, `FileStats::move_from` переносит `fileType_`,
  legacy-терминология в `DacBaselineRollback.h`; тесты `ModeAndOwnerTests`
  +2 (fd-leak через `/proc/self/fd` 100×5 объектов, directory substitution
  apply+backend rollback для обеих политик), `RollbackExecutorTests` +1
  (directory substitution → Conflict, объект нетронут, journal активен).
- Journal-lifecycle follow-up (`728262c`): матрица Prepared/commit/discard в
  `applyWithBaselineJournalProvenance` (failure+unchanged → discard, fail
  closed при ошибке discard); `ModeAndOwnerTests` +3 (failed no-op apply без
  Prepared, 10 повторных failed apply без роста journal, partial mutation
  → ровно 1 активная Prepared), `RollbackExecutorTests` +1 (wrapper partial
  apply → executor rollback → provenance активна → после починки объекта
  повторный rollback Success и journal resolve).

## Changed areas

- `fic-common/fic-core/src/fs/FileStats.cpp` (move_from/fileType_)
- `fic/src/platform/` (PlatformProfile.h, PlatformCompatibility.cpp,
  profiles/*)
- `fic/src/modules/dac/mode_and_owner/` (ModeAndOwner.*,
  DacBaselineRollback.* [новый], policies/DAC_systemcommandlock.cpp,
  policies/DAC_blocking_user_access_to_system_files.*)
- `fic/src/rollback/` (MutationRecord.h, MutationJournal.cpp,
  RollbackExecutor.*)
- `tests/` (ModeAndOwnerTests, RollbackExecutorTests,
  PlatformProfileTests, static_checks.py, CMakeLists.txt)
- `docs/rollback.md`, `docs/HANDOFF.md`

## Validation

- Full build `build-check` (ubuntu-24.04): exit 0.
- Full CTest: 96/96 passed (1 pre-existing skip `command_hash_batch_tests`).
- Целевые бинарники: `mode_and_owner_tests` (вкл. 3 новых journal-lifecycle
  теста), `rollback_executor_tests` (вкл. новый wrapper-partial-apply
  lifecycle тест), `mutation_journal_tests`, `platform_profile_tests` — exit 0.
- Regression value: при имитации старой логики (failure → Prepared всегда
  остаётся) тест `testFailedNoOpApplyLeavesNoPreparedRecord` падает; при
  имитации always-discard падает partial-тест (Prepared удалён) — матрица
  покрыта с обеих сторон.
- `bash scripts/run-development-checks.sh fast`: exit 0.
- `git diff --check`: clean.
- Sanitizers: ASan/UBSan-профиля в проекте нет — не запускались.

## Remaining

- Review и коммит незакоммиченного journal-lifecycle diff (поверх `728262c`).
- ALT p11: подтвердить `rpm -q --dump cron` (/etc/crontab), coreutils,
  e2fsprogs, net-tools, iproute2 — environment был отрезан Anubis от
  packages.altlinux.org; baseline-комментарии в AltP11Profile.cpp.
- `/etc/securetty` Debian/Ubuntu больше не поставляется (util-linux) —
  baseline 0600 сохранён по ТЗ; при желании пересмотреть.
- Partial-failure rollback из-за ОШИБКИ chown/chmod (а не type-conflict) всё
  ещё не покрыт unit-тестом (нужна root-фикстура); type-conflict вариант
  теперь покрыт (`testDacWrapperPartialApplyResolvesAfterRollback`).
- Daemon-level integration disable-теста (enable→apply→disable через
  main_function) в репозитории нет; executor-level эквивалент покрыт.
- Пункт HANDOFF «Результат отката» про legacy-ENABLE install — по-прежнему
  открыт (см. предыдущую сессию).