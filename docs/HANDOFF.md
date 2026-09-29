# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `5199613` («Follow-up к последнему коммиту №2» —
  Step 7B, 7C, 7D и follow-up'ы №1–№2 закоммичены).
- Рабочее дерево содержит **follow-up Step 7D №3** (semantic cleanup:
  whole-token pwhistory presence flags + typed case-insensitive
  canApplyFlag), изменения НЕ закоммичены. Коммит НЕ делать без явного
  запроса.

## Current task

**Step 7D + follow-up'ы №2–№3 (выполнены, не закоммичены):** Step 7D —
`password_history_depth →
pam_pwhistory → remember` переведён на journal-backed
`PamProviderManagedEntryExecutor` с placement **Beginning** на
ProviderConfigFile + PamAuthUpdate платформах (Debian 13 / Ubuntu 24.04 /
Ubuntu 26.04). Executor и Step 7B state machine не менялись.

### Routing / placement

- TOTAL helper `pamProviderManagedEntryPlacement(provider, capability,
  binding, feature) -> std::optional<Placement>` — ПОЛНЫЙ единый
  routing+placement контракт: configurationMode != ProviderConfigFile →
  nullopt; binding.syntax != Assignment → nullopt; затем whitelist:
  PamFaillock + 3 скаляра (7B) → End; PamPwquality + 9 скаляров (7C) →
  End; PamPwhistory + PasswordHistoryDepth + PamAuthUpdate (7D) →
  Beginning; всё остальное → nullopt (включая Flag-биндинги,
  ModuleArguments/ALT-топологии и чужие фичи). Silent-End fallback
  УДАЛЁН. `usesPamProviderManagedEntry` — THIN WRAPPER над helper'ом
  (routing-equality invariant зафиксирован тестом на representative
  matrix).
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
  = PAM_IGNORE, unknown/valued-flag argv → fail closed. Follow-up 7D:
  option NAMES в argv сравниваются case-insensitive как upstream —
  try_first_pass/use_first_pass/use_authtok (ASCII equals,
  весь токен: valued-вариант остаётся unknown → fail closed),
  authtok_type= (ASCII icase prefix), debug/enforce_for_root/remember=/
  retry=/file= (lowercaseCopy — фактически icase). `conf=` остаётся
  CASE-SENSITIVE prefix (upstream pam_str_skip_prefix, не icase):
  `CONF=...` НЕ является селектором и fail-closed как unknown argv;
  verifyExternalConfigContract/uniqueArgumentValue тоже case-sensitive.
- Descriptor PamPwhistory: `Semantic::Generic` → `Semantic::Pwhistory`
  (новый вариант enum). `backendFor`: ModuleArguments →
  pwhistoryArguments с ПРИОРИТЕТОМ (D12 не задет).
- **Follow-up 7D №2 (duplicate-argv invariant):** Pwhistory typed
  evaluator rejects duplicate known PAM argv options case-insensitively
  before state evaluation. Upstream last-wins semantics are modeled only
  after the argv set has passed FIC's stricter uniqueness validation.
  `PwhistoryConfigEvaluator::validatePamArguments` вызывается в
  evaluateInvocation / evaluateInvocationWithManagedOption ДО topology/argv
  application и в pwhistoryCanApplyFlag (legacy-writer preflight). Kind'ы
  (classifier `classifyPwhistoryPamArgument`): try_first_pass /
  use_first_pass / use_authtok (ASCII equals, весь токен), authtok_type=
  / remember= / retry= / file= (ASCII icase prefix), debug /
  enforce_for_root (ASCII equals; valued-варианты остаются в своём kind —
  valued-flag rejection происходит в application pass) — все icase,
  uniqueness строгая по kind (включая inert transport options).
  conf= uniqueness remains governed by the case-sensitive external-config
  contract (verifyExternalConfigContract); CONF= is not treated as conf=
  (unknown argv → fail closed).
- **Follow-up 7D №3 (whole-token flags + typed flag preflight):**
  pam_pwhistory argv presence flags `debug` and `enforce_for_root` are
  valid ONLY as whole tokens, matched case-insensitively. Any valued
  form, including an empty assignment (`debug=` / `enforce_for_root=`),
  is rejected fail-closed. Classifier выдаёт
  `PwhistoryPamArgumentValidity::{Valid,MalformedKnown}`: valued-формы
  флагов = MalformedKnown (в своём kind), validatePamArguments
  отвергает их ДО duplicate-проверки и ДО state evaluation с
  dedicated диагностикой `pwhistory PAM flag <token> must not have a
  value`; `applyPamArguments` больше НЕ выводит flag semantics из
  generic `name before '='` — только whole-token
  `asciiEqualsIgnoreCase(argument, "debug"/"enforce_for_root")`
  (upstream strcasecmp).
  pwhistory canApplyFlag uses provider-specific case-insensitive argv
  semantics (`verifyPwhistoryFlagArguments` + typed
  `PwhistoryConfigEvaluator::scanFlagArguments` — тот же classifier) and
  rejects an argv enforce_for_root override (ЛЮБОЙ case-вариант) before
  any ProviderConfigFile legacy mutation. canApplyFlag(false): argv
  flag occurrence → fail closed (unreachable для legacy writer),
  CURRENT config flag state НЕ является rejection reason.
  canApplyFlag(true): argv flag occurrence — НЕ конфликт (effective
  state уже true). Valued token → fail closed в preflight тоже.
  conflictingOptionsWhenDisabled (сейчас пустой для binding) при
  наличии проверяется typed icase (whole token или `option=` prefix) —
  generic case-sensitive helper больше не используется для pwhistory.
  verifyFlag postcondition остался typed effective proof через
  evaluator (icase argv учитывается по построению).
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

- `pam_provider_managed_entry_executor_tests` — 50 кейсов + follow-up 7D:
  routing/placement total-matrix (faillock/pwquality/pwhistory ×
  ModuleArguments/Flag/ALT/чужие фичи → nullopt placement) и
  routing-equality invariant
  (usesPamProviderManagedEntry == placement.has_value() на 12
  representative комбинациях). Кроме того: pwhistory
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
  same-valued argv, wrong conf=, D12 backend priority). Follow-up 7D:
  argv case-регрессии (TRY_FIRST_PASS/Try_First_Pass/USE_FIRST_PASS/
  Use_First_Pass/USE_AUTHTOK/Use_Authtok/AUTHTOK_TYPE=/Authtok_Type=
  инертны — каждый вариант отдельно, дубликаты kind внутри одного
  вызова запрещены), REMEMBER=20 → 20, EnFoRcE_FoR_RoOt → flag,
  FILE= → file), valued use_authtok=x fail-closed, CONF= ≠ conf=
  (fail-closed unknown), lowercase conf= инертен. Follow-up 7D №2:
  testPwhistoryDuplicatePamArgumentsFailClosed (remember=10 remember=20 /
  remember=10 REMEMBER=20 / remember=10 REMEMBER=10 → duplicate
  diagnostic; retry/file, flags enforce_for_root/debug, inert
  use_authtok/authtok_type/try_first_pass/use_first_pass дубликаты →
  fail closed; conf=/a CONF=/b → unknown, не duplicate selector; valid
  single case-variants REMEMBER=20/RETRY=4/FILE=/foo/EnFoRcE_FoR_RoOt/
  USE_AUTHTOK/AUTHTOK_TYPE=x применяются как upstream) + backend-level:
  duplicate argv в canApplyOption (включая prospective BOF при foreign
  remember=3), duplicate conf= → external contract, conf=/a CONF=/b →
  unknown argv, duplicate enforce_for_root в canApplyFlag.
  Follow-up 7D №3: valued presence-flag tokens (debug=x / DEBUG=x /
  debug= / DeBuG=1 / enforce_for_root= / EnFoRcE_FoR_RoOt= /
  ENFORCE_FOR_ROOT=yes) → FAIL + «must not have a value», flags не
  включены; DEBUG → state.debug; смешанные valid/malformed flag argv
  (debug DEBUG=x, debug=x debug, enforce_for_root EnFoRcE_FoR_RoOt=) →
  FAIL. Backend-level: canApplyFlag(false) при argv EnFoRcE_FoR_RoOt →
  FAIL «overrides the requested disabled state», config untouched;
  canApplyFlag(true) с тем же argv → SUCCESS; все case-варианты
  (enforce_for_root/ENFORCE_FOR_ROOT/EnFoRcE_FoR_RoOt) дают один
  semantic result; valued enforce_for_root= → FAIL в preflight.
- `identity_policy_hierarchy_tests`: production-like policy BOF apply
  (rotateTestJournal 4/5/6), идемпотентность, §40 transitional flag
  smoke (legacy enforce_for_root не ломает managed block), §29 argv
  override fail-closed на уровне policy (config+journal untouched),
  §29b duplicate argv (remember=10 REMEMBER=20) → apply FAIL,
  pwhistory.conf и journal untouched — duplicate rejection до journal
  mutation. Follow-up 7D №3: §29c argv EnFoRcE_FoR_RoOt + policy
  password_history_enforce_for_root=no → apply FAIL на semantic
  preflight ДО legacy mutation (pwhistory.conf byte-identical, journal
  без flag records); §29d тот же argv + policy=yes → legacy apply
  SUCCESS (same-effective argv не блокирует enable).
- Тестовые фикстуры (makePlatform/makePasswordHistoryPlatform) binding
  descriptor default topology на временные пути + verifyCapability
  helper создаёт пустой pwhistory.conf (как для pwquality).
- tests/CMakeLists.txt: PwhistoryConfigFile.cpp добавлен во все таргеты
  с PamProviderSemanticVerifier.cpp (executor, configuration, hierarchy,
  passwdqc, wiring и др.).

## Validation (фактически выполнено, follow-up 7D №3)

- Полный build `build-check` (ubuntu-24.04) — 0 errors, 0 warnings.
- Полный CTest — **111/111 PASS** (1 skip: `command_hash_batch_tests`,
  окружение).
- Targeted: executor/block/block-file/journal/configuration/hierarchy/
  pam_password_* (slot, topology model/planner/executor, wiring,
  release)/alt_pam_* — PASS.
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
