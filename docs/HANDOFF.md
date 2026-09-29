# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `3a36687` («Приступаем к Step7C» — Step 7B, 7C и
  follow-up закоммичены).
- Рабочее дерево содержит **Step 7D** (pwhistory depth на managed-entry
  executor, BOF), изменения НЕ закоммичены. Коммит НЕ делать без явного
  запроса.

## Current task

**Step 7D (выполнен, не закоммичен):** `password_history_depth →
pam_pwhistory → remember` переведён на journal-backed
`PamProviderManagedEntryExecutor` с placement **Beginning** на
ProviderConfigFile + PamAuthUpdate платформах (Debian 13 / Ubuntu 24.04 /
Ubuntu 26.04). Executor и Step 7B state machine не менялись.

### Routing / placement

- Новый TOTAL helper `pamProviderManagedEntryPlacement(provider,
  capability, feature) -> std::optional<Placement>` — ЕДИННЫЙ источник
  whitelist'а: PamFaillock + 3 скаляра (7B) → End; PamPwquality + 9
  скаляров (7C) → End; PamPwhistory + PasswordHistoryDepth +
  ProviderConfigFile + PamAuthUpdate (7D) → Beginning; всё остальное →
  nullopt. Silent-End fallback УДАЛЁН. `usesPamProviderManagedEntry`
  выведен из helper'а (routing/placement не могут разойтись).
- `PamOptionPolicy::applyManagedProviderEntry` fail-closed при
  nullopt-placement ДО journal mutation.
- D12 (ModuleArguments → Step 6 coordinator) и ALT p11 (AltTcbManaged →
  legacy fic-pwhistory.conf) вне маршрута по typed contract, без
  distro-name проверок. `password_history_enforce_for_root` (Flag) —
  Step 7E, остаётся legacy.
- Обоснование BOF: upstream `pam_modutil_search_key` возвращает ПЕРВОЕ
  case-insensitive совпадение ключа (strcasecmp, '#' комментарии,
  разделители space/tab/'='), поэтому FIC entry обязана стоять в начале
  файла. PAM argv парсится ПОСЛЕ config (last-wins) и не перекрывается.

### Typed semantic backend (Pwhistory)

- Новые файлы `PwhistoryConfigFile.{h,cpp}`:
  `PwhistoryEffectiveState` (remember=10, retry=1 — upstream defaults;
  enforce_for_root/debug — presence-флаги; file) +
  `PwhistoryConfigEvaluator` (evaluateInvocation /
  evaluateInvocationWithManagedOption — prospective BOF override).
  First-match per key (seenKeys), unknown config keys инертны, malformed
  known directive → fail closed, argv: remember clamp [0,400], remember=0
  = PAM_IGNORE, unknown/valued-flag argv → fail closed.
- Descriptor PamPwhistory: `Semantic::Generic` → `Semantic::Pwhistory`
  (новый вариант enum). `backendFor`: ModuleArguments →
  pwhistoryArguments с ПРИОРИТЕТОМ (D12 не задет).
- Backend в PamProviderSemanticVerifier: capability/option/flag/
  canApplyOption/canApplyFlag. Ключевое: `canApplyOption` — prospective
  (BOF перекроет текущий foreign remember, конфликтует только argv);
  postcondition читает РЕАЛЬНЫЙ config. External conf= контракт —
  verifyExternalConfigContract (wrong conf= → fail до mutation).
  Отсутствующий default primary (без conf=) → fail closed (vendor
  fallback недоказуем); явный conf= на отсутствующий файл → defaults
  (upstream fidelity). SYNTHETIC capability от
  Inspector::verifyOptionOverrides/verifyFlagOverrides (без
  configTopology) корректен: читается всегда capability.configPath.
- Legacy flag path: `keyMatchMode` для Pwhistory → AsciiCaseInsensitive
  (upstream case-insensitive keys).

### Ownership / topology invariants (7D)

- Один block `provider=pam_pwhistory` в BOF pwhistory.conf; foreign
  байты (включая case-variant/duplicate `remember`) сохраняются
  byte-exact и не канонизируются. Existing primary (в т.ч. пустой) →
  PreExisting, только entry-record; absent primary → FailClosed, no
  create, no records (`ReplacesNativeTopology` сохранён). Metadata
  (mode 0600) сохраняется. NO whole-file snapshot rollback.
- Displacement (exact ownership + нарушенный placement) → безопасная
  relocation в BOF тем же mutation id; wrong body/id → AppliedDrifted
  fail closed без rewrite/relocation.
- Два throwaway-фикстурных момента: `rotateTestJournal` = независимый
  provenance namespace тестовой фазы, НЕ модель production restart
  (комментарий в тесте исправлен).

### Tests

- `pam_provider_managed_entry_executor_tests` — 50 кейсов: pwhistory
  BOF integration (foreign `remember=3/retry=4/remember=7` → effective
  10), separator ownership (LF / no-final-LF), empty vs absent primary,
  metadata 0600, displacement+relocation (same id, REMEMBER = 2
  сохранён), placement-drift ≠ body-drift, first-match duplicates,
  case-insensitive first match, crash recovery smoke [5→10; 5→10 +
  desired 20 → semantic [10,20]], AppliedDrifted smoke, semantic
  failure/no-snapshot-rollback + recovery, provider separation 3
  провайдера в одном journal. Routing/placement: ALT, D12, flag →
  false/nullopt.
- `pam_configuration_tests`: evaluator-фиделити (first-match,
  case-insensitive, комментарии/separators, defaults, presence-флаги,
  malformed fail-closed, absent primary, argv override/clamp/
  remember=0, unknown argv fail-closed) + backend-тест (prospective
  canApply, реальный FIC BOF block в verifyOption, argv override,
  same-valued argv, wrong conf=, D12 backend priority).
- `identity_policy_hierarchy_tests`: production-like policy BOF apply
  (rotateTestJournal 4/5/6), идемпотентность, §40 transitional flag
  smoke (legacy enforce_for_root не ломает managed block), §29 argv
  override fail-closed на уровне policy (config+journal untouched).
- Тестовые фикстуры (makePlatform/makePasswordHistoryPlatform) binding
  descriptor default topology на временные пути + verifyCapability
  helper создаёт пустой pwhistory.conf (как для pwquality).
- tests/CMakeLists.txt: PwhistoryConfigFile.cpp добавлен во все таргеты
  с PamProviderSemanticVerifier.cpp (executor, configuration, hierarchy,
  passwdqc, wiring и др.).

## Validation (фактически выполнено)

- Полный build `build-check` (ubuntu-24.04) — 0 errors, 0 warnings.
- Полный CTest — **111/111 PASS** (1 skip: `command_hash_batch_tests`,
  окружение).
- Targeted: executor/configuration/hierarchy/wiring/mutation_journal —
  8/8 PASS.
- `git diff --check` — чисто.
- Полный distro E2E НЕ запускался (по условию, до 7F).

## Remaining (Step 7E+)

1. 7E: `enforce_for_root` (pwquality Flag + faillock even_deny_root) —
   suppress/wrapper set-only-false; добавить flag-ветку в
   PwhistoryConfigEvaluator (state.enforceForRoot уже моделируется) и
   managed flag entry в тот же provider block.
2. 7F: rollback executor wiring + package release + unlink FIC-created
   container (snapshot-bound conditional-delete primitive ещё НЕ
   существует).
3. PAM argv override на production daemon harness end-to-end не
   прогонялся (покрыт preflight/policy-level regression).
4. Прод-apply на absent primary отказывает (FailClosed); создание
   primary требует platform-level proof contract.
5. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, passwdqc/ALT, codec, activation, D12
   coordinator/сlot writer.
6. Не коммитить без явного запроса.
