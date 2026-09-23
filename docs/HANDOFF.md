# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `62f466b`; рабочее дерево содержит Step 4
  (read-only password-attach validator), не закоммичено — оставлено для
  review. НЕ коммитить.

## Current task

- Step 4 PasswordQuality/PasswordHistory: `validatePamPasswordSlotAttach`
  в `PamSlotAttachValidator.{h,cpp}` — read-only pre-attach validation
  трёх managed password slots + Rules G/I/J. Hardening follow-up
  (P1-1..P1-4, P2-1) завершён: validator усилен и доказан тестами,
  НО из CLI (`fic --maintenance validate-pam-slots-before-attach`)
  password-вердикт ВРЕМЕННО ОТКЛЮЧЁН (P1-1): команда выполняет только
  faillock-вердикт (Step 2); comment в main.cpp документирует,
  что re-wiring отложен до Step 5 (packaging). Validator API сохранён
  и полностью покрыт тестами. К daemon registry / capability policies
  не подключён (Step 7); packaging (Step 5) не менялся.

## Step 4 контракт (`validatePamPasswordSlotAttach`)

- Файл: `fic/src/modules/identity_access/pam/PamSlotAttachValidator.{h,cpp}`
  (тот же компонент, что faillock-валидатор; общий `PamSlotAttachVerdict`).
- Capability gate: требует наличия ОБЕИХ capability configs
  (PasswordQuality + PasswordHistory) в platform profile, иначе error
  (не verdict). Config directory/state directory берутся из
  `PamAuthUpdateTopologyManagerOptions` с production default'ами
  `/etc/pam.d` и `/var/lib/pam` (зеркалит topology manager).
- Строго read-only: witness-aware journal proofs через
  `PamManagedPasswordSlotWriter::proveOwnedQuality/proveOwnedHistory`
  (`validatePersistentStateReadOnly`, никакого bootstrap/witness write),
  slot inspection через `PamManagedPasswordSlots::inspectContent` +
  `inspectHistoryPair` (missing = Unavailable = fail closed).
- Ownership consistency: Active slot <=> MatchingApplied record своего
  домена; Neutral slot => Unbound. Active без journal / Neutral с
  journal / MatchingPrepared => fail closed.
- Rule I: external selected = distro `pwquality` selected в
  `/var/lib/pam/password` (exact `Module: ` lines); external effective =
  selected AND ровно один pam_pwquality.so в parsed Primary stack
  (externalSelected != externalEffective). FIC Active quality slot +
  selected => fail closed даже если provider отсутствует в графе;
  selected без provider (и provider без selected) => fail closed
  (XOR ownership), ИСКЛЮЧЕНИЕ: единственный provider — FIC-owned
  active slot (`!(pwqualityCount == 1 && qualityActive)`).
- Rule G: контроль-flow proof, а не flattened-index. `PamControlFlowAnalyzer::
  analyzePasswordFlow()` (public) возвращает
  `PamPasswordFlowAnalysis {qualityNonBypassable, historyNonBypassable,
  historyAlwaysHasTokenProducer, violations}`; internal
  `analyzePasswordFlowInternal()` возвращает
  `enum PasswordFlowResult {Analyzed, Error}` — неизвестное control
  выражение => Error => fail closed. Token-state: sticky
  `passwordTokenProduced`, а `passwordHistoryTokenAvailable`
  снапшотится при ПЕРВОМ достижении history, чтобы producer,
  запускаемый ПОСЛЕ history, не удовлетворял инварианту (G4
  reversed-order). Все флаги участвуют в `sameState`.
- Rule J semantic checks: arg-mode — slot options (из
  `PamManagedPasswordSlotOwnership::historyOptions`):
  `effectiveRemember == 0` и `!enforceForRoot` при AllPamSubjects =>
  fail closed. Conf-mode (`ProviderConfigFile` + непустой configPath):
  typed `PwhistoryRememberState {DefaultNonZero, ExplicitNonZero, Zero,
  Broken}` через `readPwhistoryConfRememberState()` в
  `PamManagedPasswordSlotWriter` — отсутствующий файл = документированный
  nonzero default => pass; unreadable/malformed/конфликтующие дублии
  `remember` => Broken => fail closed (никакого last-wins).
- Neutral ⇔ Unbound provenance (P1-4): `enum class
  PasswordDomainJournalState {Unbound, Prepared, Applied, Conflict,
  Invalid}` + read-only `inspectJournalBindingForDomain()` в
  `PamManagedPasswordSlotWriter`; `collectActiveRecord`/
  `ensureJournalOperational` теперь const. Validator: Neutral slot
  требует Unbound journal своего домена (Quality И History);
  Applied/Prepared/Conflict/Invalid => fail closed.
- Эффективные Primary stacks строятся `PamConfiguration::
  buildEffectiveStack` по всем services password scope; include
  раскрывается инлайн, поэтому маркеры ищутся по правилам
  pam_pwquality.so/pam_pwhistory.so в flattened sequence, а не по
  include-target именам.
- main.cpp wiring: password-вердикт ОТКЛЮЧЁН (P1-1, re-wiring в Step 5);
  `validate-pam-slots-before-attach` => только faillock verdict.
- Rule G control-flow: `PamControlFlowAnalyzerTests` (G1 positive, G2
  producer bypass, G2b history bypass, G2c token bypass, G4
  history-before-producer, G5 unknown control, G6 no successful path,
  G7 substack scope); validator-level jump тесты
  (`testValidatorRejectsJumpOverHistory/JumpOverProducer/
  HistoryBeforeProducer`). Journal: `seedEmptyJournal` (полный reset
  journal+witness `.initialized` — witness file нужен до re-init,
  иначе migration branch протекает); JRN1-JRN6 provenance тесты.
  Conf-mode: `testConfModeRememberNonZeroPasses`,
  `testConfModeMissingConfigPasses`, `testConfModeUnreadableConfigFails`
  (broken non-numeric remember), `testConfModeMalformedRememberFails`,
  `testConfModeConflictingRememberFails`,
  `testProviderWithoutSelectionFails` (I3).

## Previous task context (Step 3, закрыт)
- Step 2 (`PamManagedPasswordSlots`) закрыт: typed модель трёх canonical
  slots, строгий parser/inspector (missing = Unavailable, никогда не
  Neutral; whole-file canonical grammar; независимая textual mutation-id
  canonicalization; type-safe history pair identity; renderer fail-safe —
  mutationId=0 => failure, успешный render гарантирует Active).
- Step 3 РЕАЛИЗОВАН, провалидирован и ЗАКРЫТ hardening follow-up'ом
  (4 P1 defect'а устранены — см. контракт ниже), recovery-accounting
  follow-up'ом (P1-5) и same-snapshot compensation fix'ом (P1-6 —
  см. Completed).
## Fixture evidence

### v2 — pam-auth-update mechanics (все 4 платформы)

- Production-like flow без `--force` воспроизводим: `--package`, затем
  `--enable` строго ПО ОДНОМУ профилю на вызов (combined `--enable A B`
  ненадёжен).
- `--package` при local modification: rc=0, но применение может быть
  отложено/изменено; `--enable` может переписать generated file даже
  после local modification. rc=0 ничего не доказывает — обязателен
  read-only proof resulting state после КАЖДОГО вызова.
- Tie-break sort в `/usr/sbin/pam-auth-update`:
  `Priority DESC || $b cmp $a`; сортировка выполняется дважды (все
  профили, затем enabled) → placement стабилен.
- Priorities: distro `pwquality` 1024, `unix` 256; FIC quality hook
  1024, FIC history hook 1023. Intended Primary stack:
  `pam_pwquality → include quality slot → include history slot → pam_unix`.
- `Password-Initial` вариант применяется только к позиции 0 Primary.
- pwhistory mode: Debian 12 — module-arguments; Debian 13 / Ubuntu
  24.04 / 26.04 — config-file (`/etc/security/pwhistory.conf`, дефолты
  `remember = 0`, `retry = 1`). Дистро pwhistory-профиля нет;
  `pam_pwhistory.so` входит в `libpam-modules`.
- r6-v2: history hook первым с `use_authtok` на позиции 0 — intended
  enforcement молча отсутствует (основа для G).

### v3 — behavioral (/tmp/pam-gate-v3/, debian:12 + ubuntu:24.04)

Методика: пробы `chpasswd` (root) с `enforce_for_root`; ground truth —
byte-compare `/etc/shadow` (rc у stock chpasswd НЕ индикатор: без
`enforce_for_root` для root модули только предупреждают — `BAD PASSWORD`
печатается, rc=0, shadow меняется; с `enforce_for_root` — rc=1, shadow
не меняется). `enforce_for_root` для pwquality задаётся в
`/etc/security/pwquality.conf`, для pwhistory — module argument
(поддерживается на Debian 12, проверено). Ограничение (зафиксировано
честно): интерактивный `passwd(1)` через `script`-pty в контейнере
недостоверён (падает и на stock stack) — enforcement доказан через
chpasswd + shadow/opasswd byte-compare; интерактивная проверка — на
staging в Step 4+.

- Neutral-кандидаты в quality slot (distro pwquality выбран, history
  neutral): comment-only, empty, `optional pam_permit.so`,
  `required pam_permit.so`, `optional pam_deny.so` — все ведут себя как
  no-op: сильный пароль применяется, слабый отвергается дистро-
  pwquality (нет bypass), chpasswd/passwd не ломаются.
  `required pam_deny.so` — ФАТАЛЬНО (отвергается даже сильный пароль):
  механический перенос pam_deny из auth stack запрещён подтверждённо.
- Include comment-only/empty файла — no-op на ЛЮБОЙ позиции, включая
  позицию 0 (r3). Отсутствующий include target — тихий no-op, пароль
  меняется (r3): «файл всегда существует» — обязанность packaging +
  FIC validator, PAM сам не fail-closed.
- History active за neutral/empty/optional-permit include (r1,
  обе платформы, arg-mode и conf-mode): новая пара применяется, повтор
  отвергается, `/etc/security/opasswd` наполняется — history полностью
  функционален за include-target в обеих позициях стека.
- FIC quality как единственный producer (r2, distro pwquality
  де-селектирован): weak отвергнут FIC pam_pwquality, повтор отвергнут,
  opasswd=1 — FIC slot производит token, history потребляет.
- external pwquality + FIC history (r4, deb12 arg-mode + u2404
  conf-mode): weak отвергнут, новые приняты, повтор отвергнут,
  opasswd=1 — first-class topology подтверждена на обеих storage-ветках.
- history-only (r5, deb12): history hook на позиции 0, initial slot без
  use_authtok — механически enforce`ится, но это non-canonical вариант;
  вместе с r6-v2 (use_authtok первым = тихий no-op) даёт решение G.
- Lifecycle (deb12): `--enable hook` → include в generated; `--disable
  hook` → generated detached, slot-файл на диске не затрагивается;
  повторный `--enable` → restored. Идемпотентно, слотовые файлы не
  перезаписываются pam-auth-update.

## Design resolution A/B/C/G/I/J = RESOLVED

### A — permanent hook topology (Candidate 1: permanent hooks + neutral/active slots)

Package infrastructure (`/usr/share/pam-configs/`, `Default: no`,
`Password-Type: Primary`, dual stack `Password` + `Password-Initial`):

- `fic-password-quality-hook`, Priority 1024: оба блока содержат
  `include fic-password-quality` (ОДИН slot на оба варианта:
  pam_pwquality не потребляет token, use_authtok ему не нужен;
  подтверждено distro-профилем и r2, где slot включён в оба блока).
- `fic-password-history-hook`, Priority 1023: `Password` →
  `include fic-password-history`; `Password-Initial` →
  `include fic-password-history-initial`.

Managed slots (conffiles `/etc/pam.d/`, FIC-owned, существуют всегда):

- `/etc/pam.d/fic-password-quality` — capability enable_password_quality.
- `/etc/pam.d/fic-password-history` — enable_password_history, normal
  variant (достижим только при позиции hook > 0); canonical active body
  содержит `use_authtok`.
- `/etc/pam.d/fic-password-history-initial` — initial variant
  (достижим на позиции 0); canonical active body БЕЗ `use_authtok`.

Policy-owned: тела slot, решение об активации hook, journal. Не
FIC-owned: выбор дистро-профилей админом, generated `common-*`,
механика pam-auth-update. Hook selection — activation-инфраструктура,
идемпотентная: активация capability = enable hook + active body;
отключение = neutral body (hook остаётся selected). Это даёт стабильный
placement, slot body как single source of truth, тривиальный
crash-recovery и безопасный lifecycle.

Отвергнутые кандидаты:
- Candidate 2 (единый hook с двумя include): не даёт независимой
  активации quality vs history и требует partial-state semantics одного
  hook-профиля; validator сложнее.
- Candidate 3 (mutable selection: hook selected только в active):
  ownership/recovery снова зависят от pam-auth-update selection state,
  переход neutral↔active = mutation selection, crash между deselect и
  slot-write оставляет неоднозначное состояние, package-level permanent
  модель (faillock-аналог) ломается.

### B — exact managed slot set

Три файла выше — полный набор. Обоснование:
- quality/history НЕ делят slot (независимые capabilities, независимая
  activation, разные module lines);
- quality-initial не нужен (pam_pwquality не потребляет token — один
  slot на оба блока);
- отдельный neutral-marker файл не нужен (маркер — часть тела slot);
- mutable — все три тела; conffiles — все три; hook-профили — package
  infrastructure, не conffiles-мутируемые FIC.

### C — canonical neutral state

Canonical neutral body (все три slot, exact bytes):
`# FIC managed password slot: state=neutral` — одна comment-строка, ни
одного PAM rule. Behavioral proof: include comment-only файла = no-op
в любой позиции; слабый пароль отвергается активным провайдером, сильный
применяется; degenerate (оба slot neutral) безопасен (r1/r3).
Отвергнуты: empty file (валидный no-op, но неотличим от потерянного тела
и не несёт маркер), `required pam_permit.so` (поведенчески эквивалентен,
но лишний rule без пользы), `optional pam_deny.so` (no-op, семантически
вводит в заблуждение), `required pam_deny.so` (фатален, N6).

### G — use_authtok invariant (history-only = Option B, Unsupported)

- Canonical: normal slot ВСЕГДА содержит `use_authtok`; initial slot
  ВСЕГДА без него. `use_authtok` исполняется только при существующем
  token (позиция > 0 + producer перед history).
- history-only состояние (history hook selected, НЕТ ни одного
  pam_pwquality в parsed Primary password stack) — UNSUPPORTED:
  activation fail-closed (pre-attach validator rejection), registry
  semantics отражают Unsupported без token producer; зависимость
  history→quality ОБЯЗАТЕЛЬНАЯ, не Recommended.
- Обоснование: use_authtok первым = тихий no-op enforcement (r6-v2);
  обходной non-canonical вариант (r5-v3) требует третьего варианта тела
  и теряет enforcement при topology drift. Silent degradation
  security-capability недопустима product-wise.
- Validator правило (Step 4): в parsed Primary password graph перед FIC
  history include обязан существовать token producer — pam_pwquality
  (из distro-профиля или из FIC quality slot body).

### I — external distro pwquality

- «External provider present» = distro `pwquality` профиль selected в
  `/var/lib/pam/password` И pam_pwquality.so присутствует в parsed
  Primary password stack.
- enable_password_quality при external present: capability Effective,
  owner external; FIC quality hook НЕ активируется; topology не
  мутируется; journal ownership не создаётся; второй pam_pwquality не
  появляется; повторный вызов идемпотентен (no-op success, без
  claiming ownership).
- FIC quality hook активируется ТОЛЬКО когда external отсутствует и
  capability включён (тогда FIC становится провайдером). Дубликат
  предотвращается правилом activation + validator (Step 4) «не более
  одного pam_pwquality.so в Primary password stack».
- Option ownership ≠ topology ownership: PasswordQuality option policies
  продолжают управлять `/etc/security/pwquality.conf` при любом
  провайдере (current semantics; `enforce_for_root` в conf работает и
  на Debian 12 — проверено v3).
- Drift: если external исчез при включённой FIC quality capability —
  reconciliation активирует FIC quality hook (FIC становится
  провайдером) либо capability классифицируется degraded по общей
  семантике validator; silent no-op недопустим.

### J — Debian 12 authoritative option storage

- Debian 12 (module-arguments): `remember=` и `enforce_for_root` живут
  ТОЛЬКО в телах FIC slot: normal — `pam_pwhistory.so use_authtok
  remember=N enforce_for_root`; initial — `pam_pwhistory.so remember=N
  enforce_for_root`. Записи в `/etc/pam.d/common-password` ЗАПРЕЩЕНЫ
  (generated file никогда не мутируется FIC напрямую).
- Debian 13 / Ubuntu 24.04 / 26.04 (conf-mode): option storage —
  `/etc/security/pwhistory.conf`; тела slot статичные canonical
  (`use_authtok` в normal, без — в initial).
- Authoritative state ОДИН (логические опции remember / enforce_for_root
  хранятся в journal + маркере ОДИН раз); ОБА файла (normal+initial)
  генерируются транзакционно из этого состояния → divergence
  normal/initial невозможен по построению; rollback восстанавливает
  exact prior bytes обоих файлов (journal snapshot, модель faillock).
- Preflight перед option mutation: маркер slot-файла совпадает по
  capability + mutation id с journal (ownership check), иначе
  fail-closed.

### D/E/F/H (уточнения в необходимом объёме)

- D (контракт, parser — Step 3): active slot обязан нести маркер:
  version, capability, slot identity, mutation id, canonical body
  (comment-строки тела slot).
- E: Password-Initial обеспечивается dual-stack hook-профилями; initial
  вариант pwhistory не потребляет token (позиция 0).
- F: token создаёт первый token-producing модуль (pam_pwquality —
  distro или FIC); history потребляет через use_authtok (normal slot);
  pam_unix — terminal provider/consumer. Доказано r2/r4.
- H: quality никогда не ставит use_authtok; history normal slot всегда
  use_authtok; порядок quality → history → terminal provider
  гарантирован приоритетами; history функционален за любым neutral
  include (r1 H-фаза).

## Final decision matrix

| State | Supported? | Owner quality | Owner history | Token producer | History rule | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| external quality only | Yes | external | — | distro pam_pwquality | n/a (slot neutral) | baseline; FIC quality hook не активируется; опции — pwquality.conf |
| external quality + FIC history | Yes (first-class) | external | FIC | distro pam_pwquality | use_authtok в normal slot; опции per-mode storage | intended Debian/Ubuntu сценарий; r4 |
| FIC quality only | Yes | FIC | — | FIC pam_pwquality (slot body) | n/a (slot neutral) | только при отсутствии external; r2 |
| FIC quality + FIC history | Yes | FIC | FIC | FIC pam_pwquality (slot body) | use_authtok; оба slot FIC | r2 |
| history only | No — Unsupported | — | activation rejected | отсутствует | validator reject (fail-closed) | r6-v2 + r5-v3; silent degradation недопустима |

Состояние «quality и history выключены» (все slot neutral) — валидный
neutral baseline, hook-include no-op.

## Accepted architecture / invariants

- Faillock permanent-hook proof (`fic_prove_permanent_hooks_attached`,
  генерируется `write_pam_hook_proof_function` в
  `packaging/deb/build-fic-debian12-deb.sh`, строго read-only) — модель
  для password hooks: selection = exact `Module: <profile>` в
  `/var/lib/pam/password`; attachment = exact `include <slot>` rule в
  parsed generated common-password; prefix/suffix collision, wrong
  facility, комментарии, не-include control words не доказывают
  attachment; пруф никогда не вызывает PAM tools и не мутирует PAM
  state. Авторитетное описание: `docs/pam-owned-faillock-slots.md`.
- PasswordHistory managed topology строится по модели faillock:
  permanent dual-stack hook-профили + всегда существующие FIC-owned
  slot-файлы (neutral/active body) + journal-bound ownership; маркер
  (version, capability, slot identity, mutation id, canonical body) —
  в comment-строках тела slot.
- rc=0 от pam-auth-update ничего не доказывает; обязателен read-only
  proof resulting topology (selection + generated includes + slot
  bodies + journal) после каждого вызова.
- Validator invariant: exact resulting state, НЕ file provenance.
- Placement proof — semantic (relative ordering: quality provider →
  FIC quality include → FIC history include → terminal provider), без
  привязки к line numbers / jump counts; `[success=N]` динамический.
- Для password Permanent hooks FIC владеет ТОЛЬКО slot-файлами; FIC
  никогда не мутирует generated `common-password`, `/var/lib/pam/*`
  и дистро-профили; `--force`, `--remove`, `--package --remove`
  недопустимы в maintainer scripts (только production flow `--package`
  + single-profile `--enable`).
- Не более одного pam_pwquality.so в Primary password stack (external
  XOR FIC provider). pwhistory не первый PAM-модуль password stack в
  canonical active состояниях; history-only — Unsupported (fail-closed).
- Отсутствующий slot-файл — тихий no-op для PAM (не fail-closed):
  существование файлов обязана обеспечивать packaging + validator.

## Step 3 контракт (`PamManagedPasswordSlotWriter.{h,cpp}`)

- Домены: `PamManagedPasswordDomain{Quality, History}`; canonical specs
  резолвятся ТОЛЬКО внутри через `PamManagedPasswordSlots`; публичный API
  не принимает произвольных slot specs; пути ограничены canonical slot
  filenames внутри test-injectable `configDirectory`.
- P1-2 canonical domain identity: публичный конструктор НЕ принимает
  `PolicyRef`; canonical policy выводится внутри из домена
  (`canonicalPolicyRef(domain)`: Quality → `IDENTITY_ACCESS/PAM/
  enable_password_quality`, History → `enable_password_history`);
  произвольная комбинация domain ↔ policy непредставима через API.
- Journal operational gate (P1-1): mutation-пути требуют
  `usable() && lifecycleInitialized()`; raw `load()`
  (usable без witness-aware lifecycle) операционно НЕ доверяется — writer
  проходит `initializeOrLoad()` и ПОСЛЕ него повторно проверяет оба флага
  (само возвращённое true не принимается).
- Journal read-only gate (P1-1): при usable без lifecycleInitialized
  `proveOwnedQuality`/`proveOwnedHistory` вызывают строго не-мутирующий
  `validatePersistentStateReadOnly()` (проверяет pair J+W, ничего не
  создаёт/чинит; при valid pair устанавливает lifecycleInitialized) и
  после него требуют оба флага; иначе proof fail closed. Read-only proof
  НИКОГДА не создаёт witness и не мигрирует `J exists + W missing`.
- Ownership: `PasswordSlotJournalBinding{Unbound, MatchingApplied,
  MatchingPrepared}`; `owned()` == только MatchingApplied;
  MatchingPrepared — binding компенсации, НЕ ownership. Proof требует
  exact canonical Active physical state + exact mutation id + valid
  Applied journal record с exact metadata (canonical policy ref (P1-2),
  Pam backend, `capability/<policy>`, payload `UndoDisablePamCapability
  {capability, PamAuthUpdate, activationIdentifiers == permanent hook
  profile id домена}`). Same id с чужим доменом/метаданными => fail
  closed.
- P1-3 journal payload: `activationIdentifiers` НЕсут pam-auth-update
  permanent hook profile id — Quality → `["fic-password-quality-hook"]`,
  History → `["fic-password-history-hook"]` (один dual-stack профиль для
  обоих physical slots). Physical slot filenames (`fic-password-quality`,
  `fic-password-history`, `fic-password-history-initial`) в journal
  payload НЕ попадают. Step 3 journal payload использует final permanent
  hook profile IDs; текущие platform profile activationIdentifiers
  остаются legacy до integration шага (platform profiles в этом
  follow-up не менялись).
- Read-only `proveOwnedQuality` / `proveOwnedHistory`: не чинят journal,
  не пишут witness, не переводят Prepared→Applied, не переписывают slots;
  используют `validatePersistentStateReadOnly` (без bootstrap/witness).
- Activation: Prepared BEFORE physical mutation → write
  (`PamConfigFileTransaction::mutate`, rejectSymlink, PreserveExisting)
  → fresh disk re-read → strict proof exact id → journal Applied.
  History = ОДНА logical mutation (один Prepared/ID в обоих markers,
  один options object); оба snapshot до записи; failure второго write
  восстанавливает exact prior bytes первого; после обоих writes — fresh
  read обоих + `inspectHistoryPair` + options equality.
- Idempotence: Applied + exact Active physical state => success без
  нового mutation id, без rewrite (`changedSystemState == false`);
  history — дополнительно совпадение options; другие desired options
  при proven Applied pair => fail closed (без молчаливого rewrite).
- Recovery matrix при activation над Prepared record:
  A) Neutral slot(s) => prove durability
     (`ensureTargetDurableIfCurrentState`) + discard.
  B) Quality Active(same id) / history pair Active(same id, same
     options) => prove durability + complete to Applied (тот же id).
  C) History crash-partial (один слот Active(exact id), другой Neutral)
     => neutralize ТОЛЬКО exact-id слот + fresh neutral proof + discard
     + fresh activation с НОВЫМ id. Physical neutralization
     аккумулируется в `changedSystemState` (P1-4). Foreign-id/mixed/
     Broken partial => fail closed, `changedSystemState == false`.
  D) Active(other id) / Broken / Unavailable / multiple active records /
     RollbackFailed => fail closed, ничего не мутируется.
- Fresh activation: Unavailable/Broken start => fail closed (packaging
  должна предоставить файлы; missing != Neutral); canonical Active без
  matching journal provenance => fail closed, байты не трогаются, никогда
  не adopt/neutralize.
- Failure compensation: exact rollback всех attempted snapshots в
  обратном порядке (rollback() no-op для не-закоммиченного) + discard
  Prepared только если rollback доказан. Rollback не доказан => Prepared
  остаётся (existing lifecycle), `changedSystemState = true`, никогда не
  чистый failure.
- `changedSystemState` (P1-4 accumulated accounting): true только когда
  физическое состояние изменилось относительно начала ВСЕГО top-level
  вызова и не полностью компенсировано. Accounting накапливается ЧЕРЕЗ
  фазы: Prepared crash-partial recovery (`recoverBrokenHistoryPair`
  после proven physical neutralization выставляет
  `changedSystemState = true` немедленно — включая случай, когда
  последующий `discardPrepared` или fresh activation падает) + все
  компенсированные/некомпенсированные изменения fresh activation.
  Recovery neutralization + свежая фаза, упавшая ДО первой записи =>
  `success = false, ownershipProven = false, changedSystemState = true`.
  Discard failure после neutralization: не чистый failure.
- `journalBindsPhysicalOwnership() == true` (используется Step 7).
- Fault injection (test-only): `setBefore/AfterSlotWriteHookForTests
  (slotIndex)`; 0 = quality | history-normal, 1 = history-initial;
  after-hook может tamper'ить файл (fresh-verify failure => exact
  rollback + Prepared discard).

## Tests

- `tests/fic/modules/identity_access/pam/PamPasswordSlotAttachValidatorTests.cpp`,
  target `pam_password_slot_attach_validator_tests` (tests/CMakeLists.txt;
  deps = validator.cpp + writer.cpp + slots.cpp + PamConfiguration +
  OptionFile + Composition + topologymgr + MutationJournal + provider
  files). Покрытие: all-neutral pass; Active+owned pass (quality+history
  Applied records, FIC producer в stack); history-only fail (Rule G);
  missing slot fail; broken slot fail; Active без journal fail;
  foreign-domain journal record на quality slot fail; duplicate
  pam_pwquality (external + FIC include) fail (Rule I); external
  selected+parsed при Active FIC quality fail (Rule I); selected без
  parsed provider => НЕ external, pass (v2 semantics); remember=0 fail;
  enforce_for_root=false при AllPamSubjects fail; conf-mode
  pwhistory.conf remember=0 fail; read-only fingerprint на PASS и FAIL
  путях (slots + journal + witness + stack + state file + conf).
  Примечание: тестовый writeFile пересоздаёт файлы (unlink+O_EXCL) —
  PamConfiguration кэширует parsed services в памяти между вызовами
  валидатора (один PamConfiguration на вызов, кэш не разделяется между
  вызовами, но идентичные стеки в разных тестах зависят от пересоздания
  файлов только в пределах одного вызова).
- `tests/fic/modules/identity_access/pam/PamManagedPasswordSlotWriterTests.cpp`,
  target `pam_managed_password_slot_writer_tests` в tests/CMakeLists.txt
  (по образцу pam_slot_attach_validator_tests; MutationJournal.cpp deps).
  Покрытие: quality lifecycle + idempotence; Prepared не ownership
  (read-only proof не завершает record); exact-domain matching; foreign
  Active; Broken; history pair lifecycle + options identity; options
  transition fail-closed; fault injection (before/after, второй write
  после первого committed); fresh-verify tamper; crash-partial recovery
  + foreign-id partial fail closed (с проверкой `changedSystemState ==
  false` и нетронутых байтов); idempotence без rewrite. Hardening
  follow-up добавил: journal payload identity (Quality →
  `["fic-password-quality-hook"]`, History →
  `["fic-password-history-hook"]`, canonical PolicyRef/resource);
  raw-load operational regression (virgin raw load и raw-loaded
  existing journal без witness — writer восстанавливает lifecycle через
  initializeOrLoad до mutation); read-only raw-load negative (J+missing
  W: proof FAIL, witness не создаётся, байты не трогаются); read-only
  valid-witness positive (fresh journal object, proof устанавливает
  lifecycle без записи); legacy slot-filename payload => foreign,
  proof fail closed; P1-4 regression (crash-partial recovery + fresh
  failure до первой записи => `changedSystemState == true`).
  Recovery-accounting follow-up добавил группу `neutralization
  accounting` (P1-5): B — failure компенсационной записи ДО commit'а =>
  `changedSystemState == false`, байты нетронуты; C — installed write +
  proven exact rollback => `changedSystemState == false`, entry bytes
  восстановлены и доказаны; D1 — компенсационная запись закоммичена +
  fresh proof сфейлилась (tamper после commit) => helper вернул failure
  c `changedSystemState == true`, top-level activation пробросил флаг;
  D2 — installed write + failed rollback (chmod 0555 на конфиг-каталог
  после install) => `changedSystemState == true`, neutral bytes остались.
  Уточнён P1-4 regression: before-fault хук теперь stateful (первая
  index-0 запись = recovery-нейтрализация пропускается, вторая = первый
  fresh write фейлится), т.к. компенсационная запись теперь тоже проходит
  через fault-hook seam. Same-snapshot fix (P1-6) добавил тест T1
  (concurrent foreign replacement) и переписал D2 на UID-independent
  external-replacement вариант; chmod-инфраструктура из тестов удалена.

## Completed

- Шаги 1–3 завершены. Step 1 design closure и Step 2
  (`PamManagedPasswordSlots` + tests, включая hardening follow-up:
  textual mutation id canonicalization, type-safe pair identity,
  renderer rejects mutationId=0) — см. git history и fixture evidence
  ниже.
- Step 3 реализован (контракт выше) и провалидирован.
- Step 4 реализован: `validatePamPasswordSlotAttach` (контракт выше) +
  тесты `pam_password_slot_attach_validator_tests` (15 сценариев) +
  wiring в `validate-pam-slots-before-attach` (main.cpp). Полная сборка
  всех таргетов и полный CTest: 100/101 pass, 1 pre-existing failure
  `passwdqc_config_file_tests` ("pwquality policy did not retain its
  topology-dependent state") — воспроизводится на чистом дереве без
  изменений Step 4, к задаче не относится.
- Hardening follow-up к Step 3 завершён (4 P1): P1-1 witness-aware
  journal gates (operational: `usable && lifecycleInitialized` через
  `initializeOrLoad`; read-only: `validatePersistentStateReadOnly` без
  writes); P1-2 `PolicyRef` убран из публичного конструктора
  (`canonicalPolicyRef(domain)`); P1-3 journal payload → permanent hook
  profile IDs; P1-4 accumulated `changedSystemState` через recovery +
  fresh activation. Journal schema, `MutationJournal.*`, `PamRollback.*`,
  platform profiles, packaging НЕ менялись.
- Recovery-accounting follow-up к Step 3 завершён (P1-5):
  `neutralizeSlotForPreparedCompensation()` теперь принимает
  `bool& changedSystemState` и сообщает physical-change outcome
  НЕЗАВИСИМО от success/failure. Ключевой инвариант: успешный возврат
  helper'а — НЕ точка, в которой `changedSystemState` становится
  известным; failed helper МОГ физически изменить slot (installed write
  с failed/unproven rollback либо закоммиченная запись с проваленным
  fresh proof) и обязан об этом сообщить. Ветка семантики: failure до
  write attempt => flag false; installed + proven exact restore => flag
  false (плюс новая proof-of-restore проверка после rollback: entry
  state Active(exact id) должен быть доказан заново); installed +
  failed/unproven restore => flag true; write committed => flag
  выставляется ДО post-write proof; successful neutralization => flag
  true (Case B). `recoverBrokenHistoryPair()` OR-аккумулирует outcome
  (`result.changedSystemState |= helperChanged`) независимо от
  success/failure; аккумуляция монотонна по всем фазам — флаг никогда
  не сбрасывается позже. Компенсационная запись использует тот же
  fault-hook seam, что и fresh-записи (production — hooks пусты).
  Мёртвая declaration `classifyPhysicalState()` + enum `PhysicalState`
  удалены из header (ни определения, ни вызовов не было). Quality path
  аудит: аналог дефекта отсутствует — все post-write failures идут через
  `compensateFreshFailure`, который выставляет `changedSystemState`
  до возврата; правки не требовались.
- Same-snapshot compensation fix (P1-6): proof exact Prepared mutation ID
  и conditional physical mutation выполняются через ОДИН
  `PamConfigFileSnapshot` — второй capture между proof и write удалён.
  Snapshot стал ownership proof token: transaction `mutate()` строит
  `expectedTargetState` из доказанного snapshot, поэтому concurrent
  подмена Active(A) → Active(B) после proof фейлит expectedTargetState
  precondition ДО install — foreign B никогда не нейтрализуется и не
  откатывается. Failure accounting уточнён: после failed `writeSlot()`
  helper различает `snapshot.state == Captured` (FIC replacement не был
  committed — внешняя подмена не является FIC change, `changedSystemState`
  остаётся false, rollback no-op, fail closed) и
  `MutationCommitted` (FIC установил собственную мутацию — rollback
  outcome управляет флагом: exact restore proven => false, failed/
  unproven => true). Новый UID-independent D2: после install+commit
  external replacement + hook failure → rollback отказывается трогать
  foreign state (mutated identity/content mismatch), `changed=true`
  детерминированно для root и non-root (chmod-вариант удалён). Новый
  тест T1: concurrent A→B между proof и write → FAIL, B byte-for-byte
  нетронут, `changed=false`, Prepared(A) остаётся. Все P1-5 cases
  (B/C/D1, recovery→fresh, foreign-id partial) сохранены green.
  Audit quality path: двойного capture нет — fresh-пути используют один
  snapshot для inspect и write.

## Changed areas

- `fic/src/modules/identity_access/pam/PamManagedPasswordSlotWriter.h/.cpp`
  (новый компонент; в daemon target попадает через GLOB_RECURSE).
- `tests/fic/modules/identity_access/pam/PamManagedPasswordSlotWriterTests.cpp`
  (новый), `tests/CMakeLists.txt` (новый test target).
- `docs/HANDOFF.md`.

## Changed areas (recovery-accounting follow-up)

- `fic/src/modules/identity_access/pam/PamManagedPasswordSlotWriter.h/.cpp`
  (P1-5 контракт helper'а + монотонная аккумуляция; мёртвая
  `classifyPhysicalState`/`PhysicalState` удалены; P1-6 same-snapshot
  proof + Captured/MutationCommitted failure accounting).
- `tests/fic/modules/identity_access/pam/PamManagedPasswordSlotWriterTests.cpp`
  (группа `neutralization accounting` B/C/D1/D2/T1; уточнение P1-4 regression).
- `docs/HANDOFF.md`. `tests/CMakeLists.txt` правок не требовал.

## Validation

- `rm -rf build-check && cmake -S . -B build-check
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` — ок (старый build-check имел
  невалидный кэш от другого пути, пересоздан).
- `cmake --build build-check -j4` — полная сборка, 0 ошибок.
- `ctest --test-dir build-check -R 'pam|rollback'` — 16/16 PASS
  (включая pam_managed_password_slot_writer_tests,
  pam_managed_password_slots_tests, pam_auth_update_topology_tests,
  pam_slot_attach_validator_tests, pam_capability_activation_policy_tests,
  rollback_executor_tests).
- Full `ctest` — 99/100; единственный failure `passwdqc_config_file_tests`
  воспроизводится на чистом baseline (проверено git stash) —
  ПРЕДСУЩЕСТВУЮЩАЯ проблема, не относится к Step 3, не чинилась (scope).
- `git diff --check` — чисто.

## Validation (hardening follow-up)

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` + full
  `cmake --build build-check -j4` — 0 ошибок (включая daemon target).
- `ctest -R 'pam|rollback|journal|mutation'` — 17/17 PASS.
- Full `ctest` — 99/100; единственный failure `passwdqc_config_file_tests`
  воспроизведён на чистом baseline `9e7a00e` через `git stash` —
  pre-existing, не чинился (scope).
- `git diff --check` — чисто; коммит НЕ выполнялся.

## Validation (recovery-accounting follow-up)

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` + full
  `cmake --build build-check -j4` — 0 ошибок.
- `ctest -R 'pam_managed_password_slot_writer_tests|pam|rollback|journal|mutation'`
  — PASS (все targeted tests зелёные).
- Full `ctest` — 99/100; единственный failure `passwdqc_config_file_tests`
  воспроизведён на чистом baseline `9013d8f` через `git stash` с тем же
  сообщением ("pwquality policy did not retain its topology-dependent
  state") — pre-existing, не чинился (scope).
- `git diff --check` — чисто; `git diff --name-only` — только 4
  разрешённых файла; коммит НЕ выполнялся.

## Validation (same-snapshot compensation fix, P1-6)

- `cmake --build build-check -j4` — 0 ошибок (включая daemon target).
- `ctest -R 'pam_managed_password_slot_writer_tests|pam|rollback|journal|mutation'`
  — 17/17 PASS.
- Full `ctest` — 99/100; единственный failure `passwdqc_config_file_tests`
  с тем же baseline-сообщением ("pwquality policy did not retain its
  topology-dependent state") — pre-existing, не чинился (scope).
- `git diff --check` — чисто; коммит НЕ выполнялся.

## Validation (password-validator hardening, P1/P2)

- `cmake --build build-check -j4` — полная сборка, 0 ошибок (после
  re-configure с CMakeLists без probe-таргета).
- `ctest -R 'pam_password|pam_slot_attach|pam_control_flow|
  pam_configuration|pam_managed_password|journal|rollback'` — 11/11
  PASS (включая обновлённые PamControlFlowAnalyzerTests и
  PamPasswordSlotAttachValidatorTests: G-серия, jump-тесты,
  JRN-тесты, conf-mode P2-1 тесты).
- Full `ctest` — 100/101; единственный failure `passwdqc_config_file_tests`
  — известный pre-existing baseline failure, не чинился (scope).
- `git diff --check` — чисто; коммит НЕ выполнялся.

## Remaining

- Step 5: packaging (`packaging/deb/`: hook-профили + slot targets;
  extend permanent-hook proof на password hooks; conffile registration
  всех трёх slot; slot existence гарантия); в Step 5 же — re-wiring
  password-вердикта в `fic --maintenance validate-pam-slots-before-attach`
  (см. comment в main.cpp).
- Step 6: Debian 12 module-argument writer (по J).
- Step 7: lift `PamPolicySupport::ReadOnly` →
  `RequiresTopologyActivation`; подключить `PamManagedPasswordSlotWriter`
  в `PamCapabilityActivationPolicy` (quality + history policies) по
  контракту Step 3 выше; удалить
  `legacyPamAuthUpdatePasswordTopology` bypass последним.
- Step 8: обязательные тесты (RollbackExecutorTests,
  PlatformProfileTests, PamPackagingChecks и т.д. по мере шагов).
- Step 9: docs (авторитетное описание password slots — расширение
  `docs/pam-owned-faillock-slots.md`).
- Infra: docker CLI = podman (user socket
  `/run/user/<uid>/podman/podman.sock`; при ошибке подключения —
  `systemctl --user start podman.socket` и/или экспорт `DOCKER_HOST`).
  Daemon инжектит сломанный proxy env во все контейнеры — на `docker
  run` добавлять `--env http_proxy= --env https_proxy= --env
  HTTP_PROXY= --env HTTPS_PROXY=` (или unset перед вызовом).
