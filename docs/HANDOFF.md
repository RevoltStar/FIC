# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `fcfd3266a99e7b09c93b6c6c04d4a85bf3d2471b`.
- Three-profile C2 prerm redesign и Step 6 (ModuleArguments option writer
  для pam_pwhistory) — в working tree, НЕ закоммичено.

## Current task

**Step 6 — production ModuleArguments option writer для pam_pwhistory** —
реализация завершена, real Debian 12 + Ubuntu 24.04 gates запускались
(см. Validation / Remaining).

## Joint password topology domain (главный инвариант)

**Mixed Applied+Prepared package-release recovery:** `recoverCrashLeftovers`
proves only the identities it actually recovered, then re-validates the
fresh remaining topology and lets the normal C2 `transition(false,false)`
release still-owned identities.

**Topology и option configuration — разные уровни.** Topology отвечает за
History disabled / HistoryInitial / History consumer. Option writer —
только за `remember=N` + bare `enforce_for_root` в телах FIC слотов.

## Step 6 architecture (принятые решения)

- `PamPasswordRequestedState` расширен `historyOptions`
  (`ManagedPwhistorySlotOptions`); авторитетный источник — configuration
  intent. НОВЫЙ reader `readJointPasswordDesiredState(requested, pam,
  error, confDir)` читает Q/H + depth (1..50, default
  `kPasswordHistoryDepthDefault`=5 из
  `policies/PamPasswordHistoryDepthPolicy.h`) + enforce (yes/no) из ОДНОГО
  config snapshot. Provider-config platforms (Ubuntu 24.04 —
  pwhistory.conf) оставляют options пустыми (тела слотов без аргументов).
- Executor `transition(q, h, historyOptions, ...)`: attach рендерит слот
  из requested options; после плана (и на no-op path) — in-place reconcile
  активного варианта через `historyWriter_.updateC2HistoryOptions(...)`
  ПЕРЕД финальным proof. `PamPasswordTopologyExecutorOptions::historyOptions`
  УДАЛЁН (хардкод-значений в production нет).
- Writer `updateC2HistoryOptions`: ownership gate (Active + MatchingApplied
  + role payload), идемпотентный no-op при равных опциях, Prepared
  crash-partial adoption; journal **refresh** единственной активной записи
  домена (mutation id СОХРАНЯЕТСЯ — `prepareMutation` идемпотентен по
  policy/backend/resource!). Компенсация неудач — `compensateUpdateSnapshots`:
  восстановить прежние Active байты и вернуть запись в Applied (НЕ
  discard). Completion failure после durable write — honest
  changedSystemState + exact id (следующий apply завершает).
- Option policies (`PamPasswordHistoryDepthPolicy`,
  `PamPasswordHistoryEnforceForRootPolicy`) унаследованы от новой базы
  `PamPasswordHistoryOptionPolicy` (policies/): на ModuleArguments+PamAuthUpdate
  платформах apply идёт через `PamPasswordTopologyCoordinator::
  applyJointRequestedState()` (единственный writer опций); иначе legacy
  PamOptionPolicy path. `PamOptionPolicy::platformConfig_/feature_` теперь
  protected. Wiring в `main_function.cpp` передаёт coordinator factory.
- Platform metadata: `PamModuleArgumentSupport {pwhistoryRemember,
  pwhistoryEnforceForRoot}` в `PamCapabilityConfig` (evidence-based;
  debian-12 = {true,true}, остальные — unsupported по умолчанию; reader
  fail-closed на configured `enforce_for_root=yes` без evidence).
- Rollback wiring (`RollbackExecutor`) читает ПОЛНЫЙ desired state (опции
  включительно) — rollback variant switch реаттачит history с актуальными
  configured options. Семантика задокументирована в
  `docs/rollback.md` («Managed history module arguments (Step 6)»).
- makeProduction сигнатура: `makeProduction(executables, platform, error)`.

## ReadOnly lift / wiring (без изменений)

- `passwordTopologyRuntimeMutable` = true только Debian 12 / Ubuntu 24.04;
  Debian 13 / Ubuntu 26.04 / ALT — ReadOnly.

## Validation (фактически выполнено)

- Full build `build-pwhistory-options` (ubuntu-24.04): EXIT=0.
- Full CTest: **107/107 PASS** (единственный env-зависимый skip:
  `command_hash_batch_tests`).
- Новые unit-тесты: writer W-U1..U7 + W-F1/W-F3 (option update lifecycle);
  executor M9–M17 (option change via transition: in-place update, no
  pam-auth-update, variant switch, idempotence, drift fail-closed, unowned
  fail-closed); wiring `jointDesiredStateReaderOptions` (reader + evidence
  gate + provider-config empty options).
- **Real Docker gates — все зелёные:**
  - `pam_pwhistory_options_gate.sh` — **PASS debian-12** и **PASS
    ubuntu-24.04** (O1–O6, включая функциональное доказательство
    enforce_for_root: root reuse rejected на ОБОИХ дистрибутивах).
  - `pam_c2_gate.sh` (debian-12) — PASS (нет регрессии от смены сигнатуры
    драйвера).
  - `pam_c2_wiring_gate.sh` (debian-12) — PASS W1–W9.
- `git diff --check` — clean; `bash -n` gate-скрипта — OK.

## Gate-уроки (важно для будущих real-gate сценариев)

1. Новый gate-скрипт ОБЯЗАН копировать production pam-configs профили
   (`packaging/deb/pam-configs/fic-*-hook`) в `/usr/share/pam-configs/` —
   без них `pam-auth-update --enable` молча не меняет selection, и drift
   gate корректно рвёт attach. (Уже встроено в скрипт.)
2. Тестовые пароли НЕ должны содержать алфавитных последовательностей и
   систематических паттернов: stock pwquality при user-run отклоняет
   ("too simplistic/systematic", retry=3 → PAM_MAXTRIES), при root-run —
   только предупреждает. Также избегать `$` в паролях (ломается на слоях
   shell-экранирования su/env).
3. Planner-семантика: СВЕЖИЙ history attach из no-FIC-topology идёт
   СРАЗУ в consumer-вариант (ForeignQualityPlusFicHistory); initial-вариант
   достигается только variant switch при release quality. opasswd window:
   запись старого пароля происходит при каждой успешной смене; при
   remember=N граничный reuse «выпадает» через N записей ПОСЛЕ текущей.
4. pam_pwhistory на Ubuntu 24.04 в gate-окружении тоже несёт
   module-argument опции в FIC слотах и функционально исполняет
   enforce_for_root — фактическое поведение шире прежнего предположения
   «Ubuntu = только pwhistory.conf»; координатор рендерит опции на обеих
   платформах (подтверждено гейтом).

## Remaining

1. Опционально: явные renderer-тесты M1–M8 coverage-проверка, M19
   rollback-option тест, F2/F4/F5 аналоги для update-пути.
2. Не коммитить без явного запроса.
