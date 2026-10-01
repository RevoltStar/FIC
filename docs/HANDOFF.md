# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `5e03e74...`. Поверх HEAD — **незакоммиченный
  follow-up к Шагу 7F**: 6 дефектов runtime rollback / package release +
  regression-тесты + расширение real-distro gates (см. Current task).
  Коммит НЕ делать без явного запроса.

## Current task

**Follow-up к Шагу 7F (6 дефектов) — выполнен, не закоммичен.** Поверх
завершённого Шага 7F (PAM provider managed rollback + package release,
ключевые решения ниже — приняты, не пересматривать):

- **Fix 1 (P1) zero-wrapper flag release.**
  `PamProviderManagedBlock.cpp` `releasePamProviderManagedFlag`:
  разделены `matchedCandidate` (решающий кандидат) и `authorizedUnion`
  (provenance). Валидные zero-wrapper FlagEnabled/FlagDisabled состояния
  больше не классифицируются как «entry kind не совпадает». Все
  refusal-инварианты (mutation-id proof, foreign wrapper refusal,
  authority model) сохранены.
- **Fix 2 (P1) недостижимый no-journal guard.**
  `RollbackExecutor.cpp` `checkUnrecordedOwnership`: provider-managed
  ветка (`pamProviderManagedPolicyFeature != nullptr`) перенесена ПЕРЕД
  generic capability branch; legacy enable_* capability semantics не
  тронуты.
- **Fix 3 (P1) SSOT provider primaries.**
  `pamProviderManagedPrimaryPath(s)` в `PamProviderRollback.h/.cpp`:
  eligibility = `configurationMode == ProviderConfigFile` + непустой
  `configPath`, НЕ `configTopology.has_value()`;
  `knownProviderPrimaries` в PackageRelease делегирует SSOT. Остальные
  `configTopology.has_value()` (SemanticVerifier, Inspector) — легитимный
  explicit-override use, не тронуты.
- **Fix 4 (P1) Stage-A binding whitelist + P2-1 crash recovery.**
  `PamProviderPackageRelease.cpp` preflight: container Applied + absent
  primary = recoverable (continue; Stage B идёт через
  `resolveAlreadyReleasedState`); non-Applied + absent = fail closed;
  whitelist binding states (AppliedExact/AppliedMissing/
  PreparedFreshAbsent/PreparedFreshTargetPresent/
  PreparedUpdatePreviousPresent/PreparedUpdateTargetPresent → pass;
  AppliedDrifted/PreparedConflict/неизвестное → fail closed
  «non-releasable», config/journal нетронуты). Следствие: Stage B
  re-runs полный Stage-A preflight — частичный release невозможен
  (Stage A и Stage B строго согласованы; unit-тест
  `testPartialReleaseAndRetry` обновлён на эту семантику).
- **Fix 6 (P2-2) conditional delete hardening.**
  `AtomicFileWriter.cpp` `removeIfCurrentState`: `fstat(opened fd)` +
  identity/metadata re-proof, content из proven fd, финальный
  `fstatat(dirFd, name, AT_SYMLINK_NOFOLLOW)` против proven fd перед
  `unlinkat`; расхождение → `preconditionFailed=true`, ничего не
  удалено. Residual race (окно между финальным fstatat и unlinkat)
  задокументирован в коде.
- **Test seam:** `AtomicFileWriter::setRemovePreunlinkHookForTests`.

Ключевые решения Шага 7F (принятые, не пересматривать):

- **Ownership proof.** Физическое состояние рендерится ПОСЛЕ
  `prepareMutation` (physical == journal mutation id — часть ownership
  proof). Rollback выполняет payload только если ТЕКУЩАЯ platform
  profile подтверждает identity journal-записи через ТУЖЕ typed-routing
  SSOT, что и apply. Predicat — `configurationMode == ProviderConfigFile`
  (НЕ `configTopology.has_value()`).
- **Flag-release фиксация:** foreign-состояние с активной строкой
  managed key оборачивается самим apply-transition
  (`setPamProviderManagedFlagTransition`, `createSuppressionIds`).
- **Managed-provider lock** fail-closed, требует существования
  `paths.runtimeDir`.
- Gate driver (`tests/integration/pam-c2/pam_provider_rollback_driver.cpp`)
  намеренно исключён из default build/CTest; маршруты только через SSOT
  (`PamProviderCatalog`), ничего не хардкодит.

## Completed

- Шаг 7F: runtime rollback executor + package release + conditional
  delete + packaging wiring (DEB prerm, RPM preun) + real-distro gates
  G1–G7 / A1–A6 (все пять gates PASS: debian-12/13, ubuntu-24.04/26.04,
  altlinux-11).
- Follow-up: все 6 фиксов выше.
- Follow-up unit-тесты: `RollbackExecutorTests` (+4: no-record →
  NothingToDo через production `rollbackPolicyBeforeDisable`, orphan
  entry → Conflict, orphan wrapper → Conflict, legacy enable_* остаётся
  на capability inspector), `PamProviderRollbackTests` (+4 zero-wrapper:
  applied enabled/disabled, prepared target/previous enabled),
  `PamProviderPackageReleaseTests` (+6: production-like topology
  (Harness(bool capabilityTopology), configTopology=nullopt), Stage-A
  reject AppliedDrifted/PreparedConflict, pass AppliedMissing/
  PreparedFreshAbsent, crash-after-delete recovery, Prepared absent fail
  closed), `AtomicFileWriterRemoveTests` (race-window replacement
  refused).
- Негативный контроль zero-wrapper release: существующий
  `testFlagEnabledWithWrapperConflict` (enabled + matching owned wrapper
  → conflict) — подтверждён, отдельный тест не потребовался.
- Follow-up gates: `pam_provider_rollback_gate.sh` G8/G9 (flag=true и
  flag=false БЕЗ foreign occurrence → ноль wrappers, byte-exact
  restore) и G10 (orphan no-journal disable отказывает, state нетронут,
  после restore journal — release завершается); ALT-вариант A7/A8/A9 —
  то же. Route-driven, без хардкода distro.

## Changed areas

- `fic/src/modules/identity_access/pam/` (rollback/package release/
  managed block), `fic/src/rollback/`,
  `fic-common/fic-core/.../AtomicFileWriter.*`, `fic/src/main.cpp`.
- `packaging/{deb,rpm}/build-fic-*.sh`,
  `tests/integration/packaging/PamPackagingChecks.py`.
- `tests/fic/...` (unit), `tests/CMakeLists.txt`,
  `tests/integration/pam-c2/` (driver + 2 gate-скрипта),
  `docs/rollback.md`.

## Validation (фактически выполнено)

- Полный build `build-check` (ubuntu-24.04) — 0 errors, 0 warnings
  (после всех фиксов follow-up).
- Полный CTest — **115/115 PASS** (1 skip: `command_hash_batch_tests`,
  окружение).
- `python3 tests/integration/packaging/PamPackagingChecks.py $PWD` —
  PASS (prerm C2 release wiring + PAM packaging checks).
- `git diff --check` — чисто.
- **Real-distro gates: все 5 PASS с расширенными сценариями**
  (debian-12, debian-13, ubuntu-24.04, ubuntu-26.04: G1–G10;
  altlinux-11/p11: A1–A9). Включают zero-wrapper flag=true/false
  (byte-exact restore), orphan no-journal refusal (byte-exact untouched),
  journal restore + proven release.

## Remaining

1. Финальный отчёт follow-up (11 пунктов) составлен в сессии; коммит
   НЕ делать без явного запроса.
2. Real DEB/RPM packaging build в follow-up не прогонялся (только
   `PamPackagingChecks.py`).
3. Прод-apply на absent primary отказывает (FailClosed); создание
   primary требует platform-level proof contract.
4. PAM argv override на production daemon harness end-to-end не
   прогонялся (покрыт preflight/policy-level regression).
5. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, codec, activation, D12 coordinator/slot writer.

## Follow-up добавления к Шагу 7F (важно для следующего агента)

- **Driver lifecycle:** `pam_provider_rollback_driver.cpp` теперь
  воспроизводит контракт наружного `RollbackExecutor` — после успешного
  undo помечает policy record `RolledBack` (без этого повторный fresh
  apply того же identity отказывает как AppliedDrifted — это правильно
  для production, но ломало gate-сценарии re-apply).
- **SSOT policy identity:** добавлен
  `pamProviderManagedFeaturePolicyName(feature)` (обратный lookup в
  `PamProviderRollback.h/.cpp`, общая таблица
  `pamProviderManagedPolicyNames()`); драйвер больше не использует
  синтетические имена `ficgate_*` — journal/физические маркеры/orphan
  inspection работают с теми же именами политик, что production
  (`failed_authentication_*` и т.д.).
- **Сериализация enabled-флага:** маркера `FIC_PAM_FLAG_ENABLED` НЕ
  существует; enabled state = entry с «голой» строкой ключа
  (`even_deny_root`). Проверять: `grep -qx <key>` + `FIC_PAM_ENTRY_BEGIN`.
  Disabled state = `FIC_PAM_FLAG_DISABLED` sentinel внутри entry.
- **Driver bootstrap:** каждый запуск драйвера пересоздаёт пустой
  journal dir; при mv-away/restорe журнала в gate-скриптах нужен
  `rm -rf` перед восстановлением (иначе mv вкладывает каталог).
