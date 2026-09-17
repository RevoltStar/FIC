# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `65165ef` (platform-baseline rollback для
  DAC hardening-политик).
- Рабочее дерево содержит незакоммиченный hardening follow-up к `65165ef`
  (object type safety + fd lifetime, см. Current task).

## Current task

- **Hardening follow-up к platform-baseline rollback** (незакоммичено):
  1) static `FileAccessRule` теперь проверяет `is_regular_file()` ПЕРЕД
  любыми chown/chmod в apply (`ModeAndOwner::apply`) и rollback
  (`rollbackFileAccessRule` → `Conflict`); 2) fd leak в
  `rollbackTcbTreeToBaseline` закрыт через существующий RAII `UniqueFd`;
  3) `FileStats::move_from` теперь переносит `fileType_` (без этого
  type-revalidation в TCB rollback сравнивала moved-from мусор); 4)
  терминология legacy provenance уточнена (eligible, не ownership proof).
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
  мутации (fail closed при недоступном journal), commit при изменившем
  состояние успешном apply (`ModeAndOwner::lastApplyChangedSystemState()`),
  discard при отсутствии изменений; при failed apply Prepared остаётся
  активным. ВАЖНО: внутри wrapper'а вызов `this->ModeAndOwner::apply()`
  НЕВИРТУАЛЬНЫЙ — виртуальный вызов даёт бесконечную рекурсию apply↔wrapper.
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
- Целевые бинарники: `mode_and_owner_tests`, `rollback_executor_tests`
  (53 PASS, вкл. 6 DAC из основной задачи + 1 directory-substitution),
  `mutation_journal_tests`, `platform_profile_tests` — exit 0.
- fd-тест regression value: с raw `int objectFd` (без RAII) падает с
  `before=8 after=508` fd; с `UniqueFd` — passes.
- `bash scripts/run-development-checks.sh fast`: exit 0.
- `git diff --check`: clean.
- Sanitizers: ASan/UBSan-профиля в проекте нет — не запускались.

## Remaining

- Review и коммит незакоммиченного diff (вся задача platform-baseline).
- ALT p11: подтвердить `rpm -q --dump cron` (/etc/crontab), coreutils,
  e2fsprogs, net-tools, iproute2 — environment был отрезан Anubis от
  packages.altlinux.org; baseline-комментарии в AltP11Profile.cpp.
- `/etc/securetty` Debian/Ubuntu больше не поставляется (util-linux) —
  baseline 0600 сохранён по ТЗ; при желании пересмотреть.
- Partial-failure путь DAC rollback не покрыт unit-тестом (требует
  симуляции ошибки chown/chmod на одном из объектов; возможен только под
  root-фикстурой) — семантика реализована (Partial + активная journal
  запись), но не тестирована.
- Daemon-level integration disable-теста (enable→apply→disable через
  main_function) в репозитории нет; executor-level эквивалент покрыт.
- Пункт HANDOFF «Результат отката» про legacy-ENABLE install — по-прежнему
  открыт (см. предыдущую сессию).