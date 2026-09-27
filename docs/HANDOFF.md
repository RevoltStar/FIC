# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `17593ccef3dbb0c968a6521efe2bd826885cc2bf` (Step 6
  закоммичен).
- Step 6 follow-up (P1 recovery / P2 Ubuntu semantics / P3 remember
  evidence) — в working tree, НЕ закоммичено.

## Current task

**Step 6 follow-up** — три узких исправления:

- **P1 (runtime recovery):** failure journal completion'а option update
  оставляет *selected + canonical Active + exact Prepared*. Раньше
  production executor рвал это состояние на planner-гейте F9
  (unownedSelectionsPreserved: Prepared != ownership) ДО reconcile.
  Теперь executor в `transition()` сразу после первой свежей инспекции
  (`recoverExactPreparedSelectedHistoryIfNeeded`, ДО
  requireUsableCurrentState/planner) классифицирует ровно одно
  recoverable-состояние (role selected, свой слот Active с exact
  role-bound Prepared binding, sibling history Neutral, quality без
  Prepared) и завершает lifecycle через новый writer-примитив
  `completeExactPreparedC2Slot` (только journal, тело слота НЕ переписывается,
  без pam-auth-update, тот же mutation id, без новых записей;
  Applied-вариант — идемпотентный no-op; конкурирующие active records
  домена — fail closed). После recovery — свежая инспекция + требование
  нормального owned-состояния; обычные selected-but-unowned состояния
  по-прежнему fail closed (тест F6c). Сбой completion оставляет exact
  recoverable Prepared — retry возможен. Coordinator seam:
  `setHistoryJournalCompletionFaultHookForTests` (passthrough в executor).
- **P2 (Ubuntu, Variant A):** Ubuntu 24.04 остаётся
  `ProviderConfigFile` (`/etc/security/pwhistory.conf`) с
  `moduleArgumentSupport={false,false}`; классический option-policy path —
  production. `pam_pwhistory_options_gate.sh` на Ubuntu — CAPABILITY
  EVIDENCE PROBE (гейт заголовком и verdict'ом явно это помечает);
  production ModuleArguments wiring gate обязателен только Debian 12.
  Routing-тест `optionPolicyRoutingMatchesProfileMode` + пиннинг профиля в
  PlatformProfileTests. `c2ManagedHistoryDomain()` теперь protected
  (для routing-теста).
- **P3 (remember evidence):** `pwhistoryRemember` — обязательный evidence
  gate reader'а: ModuleArguments без него → desired-state read fail closed,
  ВКЛЮЧАЯ default depth (никогда не рендерить молча). enforce_for_root —
  без изменений. `pamPolicySupport`: на ModuleArguments history capability
  Depth мутабелен только при `pwhistoryRemember`, EnforceForRoot — только
  при `pwhistoryEnforceForRoot` (иначе ReadOnly). Тесты P3a/P3b/P3c в
  `jointDesiredStateReaderOptions` + `optionEvidenceSupportContract`.

## Joint password topology domain (главные инварианты, без изменений)

- **Applied = ownership; Prepared = exact lifecycle recovery binding**
  (документировано в `docs/rollback.md`, раздел «Managed history module
  arguments (Step 6)»): Prepared никогда не авторизует detach — только
  точное завершение lifecycle. Selected-but-unowned (нет записи / чужой id /
  чужой role payload / malformed body / RollbackFailed) — fail closed.
- Mixed Applied+Prepared package-release recovery (`recoverCrashLeftovers`)
  не изменялся; unselected Prepared — зона package-release recovery.
- **Quality selected+Prepared недостижим** (проверено): attach завершает
  journal до native selection; сбой completion компенсируется (neutralize +
  discard) до выбора профиля → runtime-механизм recovery для Quality не
  нужен.

## Step 6 architecture (см. коммит 17593cc)

- Reader `readJointPasswordDesiredState` — Q/H + depth + enforce из ОДНОГО
  config snapshot; теперь также remember-evidence gate (P3).
- Executor: attach рендерит слот из requested options; post-plan in-place
  reconcile через `updateC2HistoryOptions` ПЕРЕД финальным proof; НОВОЕ:
  pre-planner exact-Prepared recovery (P1, шаг 1.5).
- Writer: `updateC2HistoryOptions` (refresh той же записи, id
  сохраняется, record count не растёт; компенсации без изменений) + НОВЫЙ
  `completeExactPreparedC2Slot` (journal-only, changedSystemState=false).
- Option policies на ModuleArguments+PamAuthUpdate идут через coordinator;
  иначе classic path. Wiring в `main_function.cpp` без изменений.

## ReadOnly lift / wiring (без изменений)

- `passwordTopologyRuntimeMutable` = true только Debian 12 / Ubuntu 24.04.

## Validation (фактически выполнено)

- Full build `build-step6-followup` (debian-12, BUILD_TESTING=ON): EXIT=0.
- Full CTest: **107/107 PASS** (env-skip `command_hash_batch_tests`).
- Новые regression-тесты: executor `F6_optionRetryPreparedCompletion`
  (fault → exact Prepared crash state → retry ЧЕРЕЗ executor → completion,
  same id, no extra record, no pam-auth-update) +
  `F6c_foreignSelectedBindingStillFailsClosed`; wiring
  `jointOptionRetryPreparedCompletion` (координатор,
  `applyJointRequestedState`) + `jointRestartRecoveryPreparedCompletion`
  (reconstruction journal+coordinator из persistent state);
  `jointDesiredStateReaderOptions` P3a/P3b/P3c;
  `optionEvidenceSupportContract`; `optionPolicyRoutingMatchesProfileMode`;
  PlatformProfileTests — moduleArgumentSupport пиннинг.
- `git diff --check` — clean.
- Real Docker gates (Step 6 follow-up):
  - `pam_pwhistory_options_gate.sh` debian-12 — PASS (production wiring);
  - `pam_c2_gate.sh` debian-12 — PASS;
  - `pam_c2_wiring_gate.sh` debian-12 — PASS;
  - `pam_pwhistory_options_gate.sh` ubuntu-24.04 — PASS (capability
    evidence probe, НЕ production wiring).

## Remaining

1. Опционально: renderer-тесты M1–M8 coverage, M19 rollback-option тест,
   F2/F4/F5 аналоги update-пути, Debian 13 / Ubuntu 26.04 gates
   (платформы ReadOnly — низкий риск).
2. Не коммитить без явного запроса.
