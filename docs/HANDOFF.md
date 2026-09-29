# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `633ab1d` («Follow-up к последнему коммиту №2» —
  Step 7B и оба follow-up закоммичены).
- Рабочее дерево содержит **Step 7C** (pwquality scalars на managed-entry
  executor), изменения НЕ закоммичены. Коммит НЕ делать без явного запроса.

## Current task

**Step 7C (выполнен, не закоммичен):** 9 scalar-политик `pam_pwquality`
переведены на journal-backed `PamProviderManagedEntryExecutor` Step 7B.
Executor не переписывался; Step 7B invariants не ослаблены.

### Routing

- `usesPamProviderManagedEntry` — typed per-provider whitelist:
  PamFaillock → 3 scalar features (7B); PamPwquality → 9 scalar features
  (minlen, minclass, usercheck, gecoscheck, difok, lcredit, ucredit,
  dcredit, ocredit). Всё остальное — legacy path: enforce_for_root (Flag,
  Step 7E), passwdqc/ALT, pwhistory (7D).
- Условия маршрута: `configurationMode == ProviderConfigFile` +
  `binding.syntax == Assignment` + feature whitelist. Descriptor pwquality
  уже содержал все 9 bindings с корректными encodings.
- Debian 12/13, Ubuntu 24.04/26.04: pwquality capability =
  ProviderConfigFile + `/etc/security/pwquality.conf` → managed path
  автоматически, без distro hardcode.

### Placement

- Новый typed helper `pamProviderManagedEntryPlacement(provider, feature)`:
  PamFaillock → End, PamPwquality → End. `PamOptionPolicy::applyManagedProviderEntry`
  больше не хардкодит End; для 7D достаточно добавить `PamPwhistory →
  Beginning` одной веткой в helper.
- EOF primary обоснование: `PwqualityConfigEvaluator` = DropInsThenPrimary
  (sorted `pwquality.conf.d/*.conf` → primary последовательно) → FIC EOF
  перекрывает все drop-ins и ранние primary assignments. PAM argv
  применяется ПОСЛЕ topology — физически не перекрывается и остаётся
  fail-closed concern semantic verifier'а (не мутируется).

### Native encoding (journal/physical хранит NATIVE body)

- Кодирование НЕ изменено: `encodePamNativeValue` в `applyPam` до routing.
- YesNoInteger: yes/no → 1/0 (usercheck, gecoscheck).
- MinimumCredit: логический минимум N → -N; 0 → 0 (lcredit/ucredit/
  dcredit/ocredit). Положительные кредиты никогда не пишутся.
- Direct: verbatim (minlen, minclass, difok).

### Ownership / topology invariants (7C)

- Один общий block `provider=pam_pwquality` в EOF primary; FIC владеет
  только своими entries. Drop-ins `pwquality.conf.d` — foreign, никогда не
  мутируются; foreign primary bytes (включая case-variant/duplicate
  assignments) сохраняются byte-exact, НЕ канонизируются и НЕ удаляются.
- Existing primary (в т.ч. пустой) — PreExisting: только entry-records,
  НИКОГДА `PAM_CONTAINER/pam_pwquality`. Absent primary — FailClosed, no
  create (`explicitConfig == Unsupported` сохранён;
  `ReplacesNativeTopology` не вводился). Metadata existing primary
  сохраняется (PreserveExisting, тест mode 0600).
- Semantic preflight (`canApplyOption`) и параметризованный postcondition
  (PamCapabilityVerifier + PamProviderSemanticVerifier +
  PwqualityConfigEvaluator) обязательны и не изменены: enforcing=0,
  local_users_only, invalid drop-ins/primary, PAM argv override,
  minlen+positive-credit interaction — всё fail-closed.
- NO whole-file snapshot rollback на managed path (7B invariant);
  final-verification failure оставляет durable recoverable Prepared + FIC
  entry, foreign bytes byte-exact.
- Step 7B crash state machine переиспользуется полностью (durable target
  first, same-id refresh, fresh second read); executor-код не дублировался.

### Tests

- `pam_provider_managed_entry_executor_tests` — 38 кейсов (было 28).
  Новые: routing matrix (9 pwquality true; enforce_for_root/passwdqc/
  cross-provider false; placement helper; absent decision), shared block
  9 политик (native bodies, drop-ins/foreign byte-exact, no container
  provenance), neighbor-id stability (difok 3→5: same id, 8 соседей
  неизменны), encoding kinds (yes/no→1/0, 0→0, 4→-4 через production
  codec), effective topology ordering (реальный evaluator: drop-in 8 /
  foreign 10 / FIC 14 → effective 14), crash-recovery smoke (12→14
  recovery; prepared 12→14 + desired 16 → semantic [14,16]), drift smoke
  (body 15 same id → fail closed, no rewrite), empty primary OK vs absent
  primary FailClosed, metadata 0600, foreign duplicates preserved,
  faillock+pwquality coexist в одном journal.
- CMake executor-тестов: добавлены PwqualityConfigFile.cpp,
  PamProviderCatalog.cpp, PamProviderMetadata.cpp,
  PamPlatformComposition.cpp, PamOptionValueCodec.cpp (evaluator + codec;
  без production closure).
- `IdentityPolicyHierarchyTests` обновлён под managed-контракт:
  initializeRuntimePaths задаёт mutationJournalFile (+ rotateTestJournal
  для фаз с внешней перезаписью pwquality.conf — иначе легитимный
  AppliedMissing fail-closed executor'а); fault-injection
  final-verification теперь ожидает recoverable Prepared + FIC entry
  вместо whole-file restore; case-variant duplicates ожидают byte-exact
  preservation + FIC EOF entry.

## Validation (фактически выполнено)

- Полный build `build-check` — PASS, 0 warnings.
- Targeted: `ctest -R 'pam_provider_managed|pam_configuration|
  mutation_journal|pam_option_value_codec'` — 6/6 PASS.
- Полный CTest — **111/111 PASS** (1 skip: `command_hash_batch_tests`,
  окружение).
- `git diff --check` — чисто.
- Полный distro E2E НЕ запускался (по условию задачи, до 7F).

## Remaining (Step 7D+)

1. 7D: pwhistory BOF placement (typed helper готов: `PamPwhistory →
   Beginning` + routing whitelist).
2. 7E: enforce_for_root (pwquality Flag + faillock even_deny_root) —
   suppress/wrapper set-only false.
3. 7F: rollback executor wiring + package release + unlink FIC-created
   container (snapshot-bound conditional-delete primitive ещё НЕ
   существует: trusted capture → strict parse → exact ownership re-proof →
   conditional delete → fsync parent dir → resolve provenance).
4. Прод-apply faillock/pwquality на absent primary отказывает (FailClosed);
   создание primary требует platform-level proof contract.
5. PAM argv override на production daemon harness end-to-end не
   прогонялся: покрыт semantic verifier regression (`pam_configuration_tests`,
   в т.ч. `testPwqualityEffectiveTopologyAndArguments`) + routing test;
   production `applyManagedProviderEntry` вызывает `canApplyOption` до
   любой journal mutation — контракт сохранён.
6. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, passwdqc/ALT, codec, descriptor'ы, activation.
7. Не коммитить без явного запроса.
