# FIC: передача контекста

## Current base

- Ветка `main`; HEAD = `ad6dd50` («Follow-up к последнему коммиту» —
  Step 7B + предыдущий follow-up закоммичены).
- Рабочее дерево содержит **второй follow-up Step 7B** (fix UB/stale-local
  state в crash window `entry Prepared` → `container Prepared`), изменения
  НЕ закоммичены. Коммит НЕ делать без явного запроса.

## Current task

**Follow-up Step 7B №2 (выполнен, не закоммичен):** fix UB в
`applyFreshCreatedContainer()` + 2 regression-теста. Два предыдущих
архитектурных исправления (durable target first; Prepared-container
witness) уже в `ad6dd50` и не менялись.

### Исправление (P0): stale `containerRecord` optional / UB

- Crash window внутри fresh FIC-created container lifecycle: entry Prepared
  persisted → CRASH → container Prepared ещё НЕ persisted → file absent.
  Это легитимное промежуточное journal состояние; recovery обязан сам
  создать недостающую container provenance (`journal.prepareMutation`
  внутри `applyFreshCreatedContainer`) до physical create.
- Bug: после успешного `journal.setStatus(containerId, Applied)` код
  refresh-хвоста делал `std::optional<MutationRecord> completedContainer =
  containerRecord; completedContainer->status = Applied;` — при исходном
  `containerRecord == nullopt` это dereference disengaged optional (UB).
- Fix: container provenance уже durably Applied на этот момент, поэтому
  refresh-хвост передаёт `containerRecord = std::nullopt` (и witness
  `nullptr`) — `completePreparedContainerProvenance` для nullopt/Applied —
  верифицированный no-op. Никаких fabricated локальных `MutationRecord`;
  caller'овский optional — stale pre-prepare state и не используется.
- Invariants: entry Prepared может легитимно существовать до container
  Prepared; recovery этого состояния создаёт недостающую container
  provenance до physical create и не полагается на stale pre-prepare
  optional caller'а; после того как container provenance стала Applied
  внутри той же операции, последующий desired-value refresh не использует
  stale входной `containerRecord` optional. Проверено и не сломано:
  `container Prepared + entry absent + file absent` → fail closed;
  `container Applied + file absent` → fail closed.

### Предыдущие исправления (в `ad6dd50`, не менялись)

**Follow-up Step 7B (выполнен):** два архитектурных
исправления в `PamProviderManagedEntryExecutor` + regression-тесты.
Routing трёх faillock scalar политик и вся структура Step 7B сохранены.

### Исправление 1 (P0): durable target first

- Раньше recovery `Prepared` (`PreparedFreshAbsent` /
  `PreparedUpdatePreviousPresent`) физически писал `request.nativeValue`
  (current desired) вместо durable journal target → proof ожидал target,
  executor сам портил recoverable state (физика C, journal 5→10 → следующий
  запуск `PreparedConflict`).
- Теперь: `performPhysicalMutation(request, nativeValueToWrite, ...)` —
  явное значение записи; recovery пишет ТОЛЬКО durable target из
  `payload->appliedBody`, извлечённый общим canonical parser'ом
  `parseCanonicalPamProviderEntryBody` + проверка `key == payload->managedKey`
  (хелпер `durableTargetNativeValue`, никакого substring surgery).
- `SemanticPostcondition` параметризована значением:
  `bool(const std::string& expectedNativeValue, std::string& error)`.
  Recovery вызывает `semantic(durableTarget)`, refresh/no-op —
  `semantic(currentDesired)`. Production lambda в
  `PamOptionPolicy::applyManagedProviderEntry` передаёт аргумент в
  `verifyPostMutationPamState` (не захватывает `nativeExpectedValue`).
- После завершения durable transition при `desired != target` — ОБЯЗАТЕЛЬНЫЙ
  fresh trusted read + strict parse + exact Applied ownership proof
  (`freshProveRecoveredAppliedState`) и только потом refresh `B→C` тем же id
  (общий хвост `refreshProvenOwnedEntry`; требует fresh read — stale
  snapshot запрещён для второй мутации).
- Fresh-create recovery (`applyFreshCreatedContainer`): при существующей
  Prepared entry physical create содержит durable target из journal;
  semantic(target); entry Applied; container Applied; затем при
  `desired != target` fresh read + refresh тем же id.

### Исправление 2 (P0/P1): Prepared container provenance

- Раньше `reconcileContainerProvenance` переводил Prepared → Applied по
  вызову caller'а: новый entry, созданный самой операцией в уже существующем
  контейнере, мог «легализовать» контейнер — circular ownership proof.
- Теперь `provePreparedContainerCreationWitness()` ДО любой физической
  мутации текущего apply сканирует ВСЕ активные entry-записи journal для
  (provider, configPath) — любая политика (cross-policy recovery) — и ищет
  pre-existing exact journal↔physical witness через Step 7A
  classifier/ownership proof. Допустимые witness-статусы (строгий набор):
  - entry `Applied` + `AppliedExact` (exact id + body);
  - entry `Prepared` + `PreparedFreshTargetPresent` /
    `PreparedUpdateTargetPresent` (физическое создание уже произошло).
  НЕ witness: `PreparedFreshAbsent`, `PreparedUpdatePreviousPresent`,
  `PreparedConflict`, `AppliedMissing`, `AppliedDrifted`, `RollbackFailed`.
- Завершение Prepared → Applied только через typed-токен
  `ProvenPamProviderContainerCreation` (`completePreparedContainerProvenance`;
  nullptr = fail closed). Exclusive-create fresh flow завершает контейнер
  собственным созданием (контейнер был proven-absent, создание эксклюзивное,
  ownership proven) — это не circular proof.
- Witness proof + завершение provenance происходят в `apply()` ДО обработки
  текущей политики; текущая политика никогда не становится evidence.

### Invariants (не ослаблять в 7C–7F)

- Для `status == Prepared` текущее значение политики НЕ имеет права менять
  unresolved transaction: сначала recover exact journal transition
  (durable target), потом reconcile current desired (fresh read, same id).
- Semantic verification параметризована target value; recovery target и
  current desired могут различаться.
- Prepared container provenance становится Applied ТОЛЬКО из pre-existing
  exact journal↔physical creation witness; никогда из entry, созданного
  текущей операцией.
- После завершения одного durable transition любой следующий refresh
  desired-value начинается с fresh trusted read/snapshot.
- Executor никогда не пишет физически без Prepared journal provenance;
  recovery всегда через classifier; no whole-file snapshot rollback;
  same-id refresh; EOF placement; absent production primary — FailClosed;
  container record независим от lifecycle creator entry ПОСЛЕ того как стал
  Applied; ≤1 active `own_pam_provider_container` на configPath.

### Tests

`tests/fic/modules/identity_access/pam/PamProviderManagedEntryExecutorTests.cpp`
— 28 кейсов (было 16). Harness semantic callback собирает
`verifiedValues` (порядок semantic-проверок) + `failSemanticFor`
(injected failures). Новые regression:
desired-changed recovery (previous-present / target-present / fresh /
fresh-created container) с проверкой semantic sequence `[10,20]` / `[5,7]`;
failure между двумя transitions → recoverable `Prepared(10→20)` + adopt
при повторном apply; prepared container без witness → fail closed
(byte-exact, контейнер Prepared, нет новых записей); creator witness
(apply A; cross-policy apply B; Applied-exact witness); wrong creator
id/body → fail closed; crash window `entry Prepared + container record
absent + file absent` — desired changed (`["5","7"]`, recovery сам создаёт
container provenance, 1 entry + 1 container + 1 physical entry, same id)
и desired unchanged (`["5"]`). Все существующие кейсы сохранены.

## Validation (фактически выполнено)

- `cmake --build build-check --target pam_provider_managed_entry_executor_tests`
  — PASS, warnings нет.
- `ctest -R pam_provider_managed` → **4/4 PASS** (включая
  `pam_provider_managed_entry_journal_tests`).
- Полный build `build-check` — PASS без warnings; полный CTest —
  **111/111 PASS** (1 skip: `command_hash_batch_tests`, окружение).
- `git diff --check` — чисто.

## Remaining (Step 7C+)

1. 7C: pwquality на этот же executor (durable-target-first и witness
   семантика уже в executor'е; absent-container для pwquality — тоже
   `ReplacesNativeTopology` → FailClosed).
2. 7D: pwhistory BOF placement; 7E: suppress/wrapper set-only false;
   7F: rollback executor wiring + package release + unlink FIC-created
   container.
3. **Step 7F contract — snapshot-bound unlink (обязательно):**
   conditional-delete primitive ещё НЕ существует: trusted capture →
   strict parse → exact ownership/provenance re-proof → conditional delete
   exact target (fail stale) → fsync parent dir → только затем resolve
   container provenance record.
4. Прод-apply трёх faillock политик на absent primary отказывает
   (FailClosed): создание `/etc/security/faillock.conf` потребует
   platform-level proof contract — отдельное архитектурное решение.
5. Не трогали: C2 topology, PamOptionFile semantics, Step 6 option
   reconciliation, Debian 12 pwhistory ModuleArguments.
6. Не коммитить без явного запроса.
