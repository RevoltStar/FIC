# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `5199613`. Рабочее дерево содержит **Step 7E**
  (journal-backed managed ownership трёх set-only PAM-флагов), изменения
  НЕ закоммичены. Коммит НЕ делать без явного запроса.

## Current task

**Step 7E (выполнен, не закоммичен):** `even_deny_root` (faillock),
`enforce_for_root` (pwquality), `enforce_for_root` (pwhistory) переведены
на journal-backed `PamProviderManagedFlagExecutor` (durable-target-first
state machine Step 7B). desired=true → bare flag в FIC provider block;
desired=false → disabled sentinel + suppression wrappers вокруг каждого
подавляемого foreign-активного вхождения (байты foreign line — в
`raw=` wrapper'а, journal хранит только provenance ids). Step 7F НЕ
начат.

### Accepted architecture / invariants

- Routing (синтаксо-осознанный): Flag-биндинги маршрутизируются ТОЛЬКО по
  7E-whitelist: faillock `FailedAuthenticationEnforceForRoot` → End;
  pwquality `PasswordQualityEnforceForRoot` → End; pwhistory
  `PasswordHistoryEnforceForRoot` + PamAuthUpdate → Beginning; foreign
  фича/топология/Assignment-синтаксис флага → nullopt. Assignment-
  whitelist 7B/7C/7D не изменился.
- Один lifecycle-элемент на policy: toggle false↔true под ОДНОЙ активной
  journal-записью (`remove_pam_provider_managed_flag`), id стабилен;
  освобождение wrappers — байт-в-байт; новые foreign-строки при disabled
  → новые ids, старые стабильны; внешне освобождённые ids канонизируются
  из provenance и НЕ переиспользуются, пока запись активна (id-namespace
  = файл ∪ journal).
- Applied refresh — no-op; дрейф (AppliedDrifted), чужой mutation id,
  неизвестный wrapper id, wrappers при enabled — fail closed. Fresh
  transaction не адоптирует pre-existing entry/wrapper. Prepared
  recovery: durable target первым, затем reconciliation под текущий
  desired (semantic callback получает durable target ПЕРВЫМ).
- Absent primary → FailClosed (no create, no records); metadata
  сохраняется; no whole-file snapshot rollback.
- Journal payload `remove_pam_provider_managed_flag`: enabled-состояние
  ⇒ пустые suppression-наборы; fresh transition ⇒ нет previous
  provenance; write/read parity (previous_applied_enabled всегда
  materialized).

### Completed

- `PamProviderManagedFlagExecutor.{h,cpp}` (новые) +
  grammar/primitives в `PamProviderManagedBlock.{h,cpp}`
  (FlagEnabled/FlagDisabled kinds, sentinel, wrapper line/parse,
  `setPamProviderManagedFlagTransition`, icase-сканер активных
  вхождений pwquality/pwhistory, faillock — case-sensitive).
- Роутинг в `PamProviderManagedEntryExecutor.cpp` переписан
  синтаксо-осознанно (см. invariants).
- Journal: write/read parity flag payload + load-time cross-field
  identity check (исправлен баг: loader не имел flag-branch — любой
  restart с флаговой записью падал бы fail closed) + §32 load-time
  cross-record suppression-id uniqueness.
- Policy wiring: `PamOptionPolicy` / `PamProviderSemanticVerifier` —
  managed flag path; pwquality/pwhistory icase flag semantics;
  argv-конфликт флага → preflight fail closed до мутации.
- Fix в `PamProviderManagedBlock.cpp` (`parsePamProviderSuppressionWrapper`):
  mid-parse reset `wrapper = T{}` затирал уже присвоенный `provider`.

### Changed areas

- `fic/src/modules/identity_access/pam/` (FlagExecutor — новые файлы,
  ManagedBlock, EntryExecutor, PamOptionPolicy, SemanticVerifier,
  PwhistoryConfigFile)
- `fic/src/rollback/MutationJournal.cpp`, `MutationRecord.h`
- `tests/.../pam/PamProviderManagedEntryExecutorTests.cpp` (routing
  matrix синтаксо-осознанный), `tests/.../pam/
  PamProviderManagedFlagExecutorTests.cpp` (новый, 19 сценариев:
  byte-exact wrap/unwrap round trips (indent/comment/=0/no-LF/CRLF/
  case), grammar/refusals, journal round-trip/validation/retry-
  identity, lifecycle §66–§76, metadata §65, restart refresh),
  `IdentityPolicyHierarchyTests.cpp` (policy-path 7E: disable→wrapper+
  sentinel block, enable→block, argv-конфликт fail closed, SET-forms,
  pwhistory flag в одном block с depth), `tests/CMakeLists.txt`
- `docs/rollback.md` — раздел «PAM provider managed flag rollback
  (Step 7E)»

### Validation (фактически выполнено)

- Полный build `build-check` (ubuntu-24.04) — 0 errors, 0 warnings.
- Полный CTest — **112/112 PASS** (1 skip: `command_hash_batch_tests`,
  окружение).
- `git diff --check` — см. финальную проверку сессии; distro E2E НЕ
  запускался (до 7F).

## Remaining

1. 7F: rollback executor wiring + package release + unlink FIC-created
   container (snapshot-bound conditional-delete primitive НЕ существует).
2. PAM argv override на production daemon harness end-to-end не
   прогонялся (покрыт preflight/policy-level regression).
3. Прод-apply на absent primary отказывает (FailClosed); создание
   primary требует platform-level proof contract.
4. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, passwdqc/ALT, codec, activation, D12
   coordinator/slot writer.
5. Не коммитить без явного запроса.
