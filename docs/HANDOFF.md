# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `82af579c72f475886529c1d9ca46db90e3abdb3f`.
- Поверх HEAD не закоммичен CI-fix synthetic support fixture и это
  обновление HANDOFF; commit не запрошен.

## Current task

Исправление CI run `36237012929`: `passwdqc_config_file_tests` должен
учитывать evidence-gated `passwordTopologyRuntimeMutable`. Выполнено.

## Joint password topology domain (главный инвариант)

**Password Quality + Password History form ONE joint runtime topology
domain.** Физическое состояние — joint (Q, H) topology (None / FicQuality /
FicHistoryInitial / FicQualityPlusFicHistory / ForeignQuality /
ForeignQualityPlusFicHistory). Запрещено и отсутствует:

- два независимых PAM activation mutation (per-policy enable/disable);
- вызов pam-auth-update вне `PamPasswordTopologyTransitionExecutor`
  (unit-seam + package scripts/maintenance tools);
- вывод desired state из физической топологии — desired = configuration
  intent (`IDENTITY_ACCESS.conf`: статусы `enable_password_quality` /
  `enable_password_history`).

## ReadOnly lift

- `PamPlatformConfig.passwordTopologyRuntimeMutable` — evidence-based
  флаг: true ТОЛЬКО на платформах с пройденными real gates + wiring gates.
  Установлен в Debian12Profile и Ubuntu2404Profile; Debian 13 / Ubuntu
  26.04 / ALT остаются ReadOnly.
- `pamPolicySupport()`: PamAuthUpdate + password capability →
  `RequiresTopologyActivation` при поднятой поддержке, иначе прежний
  `ReadOnly`. Lockout и StaticVerifyOnly (ALT passwdqc) не затронуты.
- Контракт-тест `supportContract` (pam_password_wiring_tests): по build
  platform Debian12/U2404 ⇒ lifted, остальные ⇒ ReadOnly; сброс флага
  возвращает ReadOnly; флаг не действует вне PamAuthUpdate.

## Joint daemon wiring

- `PamPasswordTopologyCoordinator` (новый): read joint config intent →
  ОДИН `executor.transition(Q, H)`. Production construction —
  `makeProduction(resolver)` поверх `DaemonMutationJournal` и дефолтного
  reader'а (`readJointPasswordConfigIntent`). Contract: caller держит
  identity configuration mutex; coordinator сам не локает (нет рекурсии
  с PamPolicy::apply).
- `PamCapabilityActivationPolicy`: password capabilities на PamAuthUpdate
  платформах идут через `passwordCoordinatorFactory`; legacy
  single-capability manager path для них недостижим (без factory — fail
  closed; StaticVerifyOnly — прежний verify-only путь).
- Daemon (`initPolicyRegistry`): activation policies
  enable_password_quality/history регистрируются на поднятых платформах;
  option-политики качества/истории автоматически получают recommended
  dependency на activation policy (PamOptionPolicy).
- Startup reconcile (`applyAllPoliciesExceptModule`) идёт через тот же
  coordinator: proven topology = no-op, drift = fail closed.
- **Исправлен production blocker в executor'е** (пойман wiring-гейтом):
  `PamPasswordTopologyTransitionExecutor` НЕ нормализовал пустые
  configDirectory/stateDirectory к `/etc/pam.d` и `/var/lib/pam`, хотя его
  контракт это декларирует — writer искал слоты относительно CWD процесса.
  Теперь пустые пути нормализуются в конструкторе (даунстрим-контракты
  инспекции уже нормализовали; writer/runner — нет). Явные пути (тесты,
  executor-гейт) не изменены.

## Transaction semantics / crash consistency

- Config persistence предшествует apply (`policy enable` → saveConfig →
  apply). Crash между persist и transition: Prepared-записи writer'а +
  recovery matrix при следующей activation. Crash после физического
  успеха: startup reconcile доказывает desired topology (no-op) или
  честно падает (drift/unsafe). Новый crash-recovery subsystem не строился.

## C2 rollback integration

- Schema journal НЕ менялась: slot-записи writer'а (payload
  `UndoDisablePamCapability` с identifiers `fic-password-*-hook`)
  остаются physical provenance; отдельный policy-level undo record не
  вводился — существующей информации достаточно.
- Детект C2-домена в `undoPamCapability` (`managedPasswordSlotDomain`):
  точный набор identifier'ов + capability quality/history + PamAuthUpdate.
  Обрабатывается ДО legacy manager path; без wiring — fail closed
  (Conflict); legacy two-profile path для C2-записей не используется.
- Rollback target: освобождаемая capability → false, ВЫЖИВШАЯ → текущий
  config intent. Rollback = ОДИН joint C2 transition (planner sequence).
  Q+H → disable quality → H-only (DetachConsumer/DetachQuality/
  AttachInitial); повторный запрос Q → variant switch DetachInitial/
  AttachQuality/AttachConsumer. Наивное «disable identifier'ов одной
  записи» осиротило бы выживший consumer.
- Wiring: `RollbackExecutorDeps.pamPasswordTopologyTransition` +
  `.pamPasswordRequestedState` (productionRollbackDeps). Совместимость
  SSH/SYSCTL/SUDO/FIREWALL/DC/faillock записей не затронута.
- Failure: transition/compensation failure → Failed → framework ставит
  RollbackFailed (НЕ RolledBack); повторный rollback после RollbackFailed
  — fail closed.
- Foreign preservation: rollback убирает только FIC-owned attach; stock
  pwquality остаётся (итог — ForeignQuality). Selected-but-unowned и
  unsafe состояния — fail closed executor'а.

## Concurrency / TOCTOU

- Semantic transition (inspect/plan/mutate/proof) сериализуется общим
  identity mutex: policy apply (PamPolicy::apply) и rollback
  (`undoPamPasswordTopology` блокирует `IdentityAccessPolicy::
  configurationMutex()` — accessor теперь public). Executor driftGate
  остаётся обязательным (external pam-auth-update); coordinator не
  кэширует физическую топологию.

## Diagnostics

Coordinator классифицирует failure: native mutation failure /
compensation ("pre-transition topology proven restored" vs "COMPENSATION
STOPPED: NOT proven restored") / partial mutation ("partial mutation may
be installed") + список proven actions. Политики пробрасывают текст без
обезличивания; unsupported platform / unsafe topology / ownership missing
различаются executor'ом.

## Accepted architecture / invariants

- Physical selection != FIC ownership; detach только journal-proven
  FIC-owned identities; foreign producer никогда не claimed/removed.
- Attach ordering: Active slot → proof → selection. Detach — обратный.
- `changedSystemState` monotonic/honest; Prepared/Applied lifecycle per
  slot activation (existing MutationJournal semantics, без изменения
  schema); common-password никогда не копируется/не snapshot'ится.
- **ReadOnly lift ВЫПОЛНЕН** (evidence-based): password capabilities на
  PamAuthUpdate платформах Debian 12 / Ubuntu 24.04 —
  `RequiresTopologyActivation` (gates G1-G11 + wiring gates W1-W9
  пройдены); Debian 13 / Ubuntu 26.04 / ALT — по-прежнему `ReadOnly` до
  своих gates. Политики доходят до физики ТОЛЬКО через
  `PamPasswordTopologyCoordinator` → C2 executor.
- Legacy prerm preflight (Temporary invariant ниже) СОХРАНЁН.

## Temporary invariant (legacy prerm, до C2 three-profile redesign)

```text
legacy prerm does NOT mutate fic-password-history-initial-hook
until three-profile C2 removal/rollback exists.
```

Обоснование (проверено по фактическому libpam-runtime на хосте): пакет не
имеет postrm; dpkg удаляет `/usr/share/pam-configs/<profile>` сразу после
успешного `prerm remove`; `pam-auth-update` (строка `@enabled = grep
{ $profiles{$_} } @enabled`) молча отбрасывает осиротевший selected-профиль
только при СЛЕДУЮЩЕЙ внешней регенерации — без FIC provenance/proof; а на
purge удаляется conffile `/etc/pam.d/fic-password-history-initial`, и
generated include повисает (broken password stack). Поэтому skip-from-remove
(Strategy A) оставлял production-reachable dangling topology — выбрана
Strategy B (preflight fail-closed). Профиль остаётся в package payload.


## Architecture gate verdict (историческое evidence, НЕ переписывать)

`tests/integration/packaging/PamArchitectureGate.sh` остаётся в репозитории
как историческое доказательство.

Важно различать:

- Gate ПРАВИЛЬНО опроверг topology **permanent selected comment-only
  neutral hooks** (постоянно выбранные high-priority профили с
  нейтральными comment-only слотами): они занимают provider-позицию без
  семантического модуля и ломают chpasswd.
- Позднее v7-эксперименты владельца валидировали ДРУГУЮ topology —
  **activation-time semantic producer/consumer hooks (C2)**. Gate не был
  "неправильным": он опроверг именно permanent-neutral дизайн.

## C2 experimental evidence (owner-run v7, Debian 12 + Ubuntu 24.04)

Источник истины для этого этапа. Серия экспериментов владельца проекта,
финальная версия v7.

### Почему ранний вариант C падал

High-priority FIC Primary profile вытеснял stock `pam_unix` из initial
provider position (modpos 0). Stock unix профиль имеет формы:

```text
Password-Initial:  pam_unix.so obscure yescrypt                            # producer
Password:          pam_unix.so obscure use_authtok try_first_pass yescrypt # consumer
```

При более приоритетном FIC-профиле pam_unix становится consumer
(`use_authtok`). Если FIC profile/slot при этом semantic no-op
(comment-only neutral), никто не создаёт `PAM_AUTHTOK` ->
`pam_chauthtok` fails. Ключевой corrected conclusion:

```text
Activation-time hook НЕ сломан концептуально.
Сломана topology, в которой high-priority initial profile
не выполняет обязанности token producer.
```

### v7: рабочая C2 producer/consumer topology

Quality-only:

```text
fic-password-quality (pam_pwquality.so)  -> produces/checks PAM_AUTHTOK
pam_unix.so ... use_authtok
```

Подтверждено на Debian 12 + Ubuntu 24.04: strong -> PASS, weak -> REJECT,
ordering ficQ < unix, disable -> baseline restored.

History-only: история БЕЗ существующего producer сама является initial
producer (`fic-password-history-initial`, `pam_pwhistory.so remember=N`
БЕЗ `use_authtok`):

```text
pam_pwhistory (producer + history check)
pam_unix ... use_authtok
```

Подтверждено: normal change -> PASS, reuse -> REJECT, disable -> baseline
restored. Следовательно старое предположение "history requires quality"
НЕВЕРНО. Новое правило:

```text
history requires a token producer.
если producer отсутствует:    history itself = producer
если producer уже существует: history = consumer
```

Quality + History:

```text
fic-password-quality (pam_pwquality)
fic-password-history (pam_pwhistory use_authtok)
pam_unix use_authtok
```

Подтверждено: strong -> PASS, weak -> REJECT, reuse -> REJECT, physical
order ficQ < ficH < unix.

### Foreign / stock pwquality — часть принятой архитектуры

Foreign quality pre-existing: если stock `pwquality` уже выбран ДО
activation FIC — FIC НЕ добавляет второй quality producer (topology
no-op: stock stays selected, fic-password-quality-hook stays unselected).
При requested history:

```text
stock pwquality
fic-password-history   # use_authtok
pam_unix
```

v7 подтвердил: stock selection сохраняется, FIC quality hook не
включается, history работает, weak/reuse reject работают, rollback FIC
history не снимает stock pwquality, исходный foreign state
восстанавливается byte-exact.

Foreign state появляется ВО ВРЕМЯ активности FIC (provenance invariant):

```text
initial: no stock pwquality
FIC: enables fic-password-quality
admin: enables stock pwquality
FIC policy disabled: remove ONLY fic-password-quality
result: stock pwquality + pam_unix (совпадает с independent stock-only oracle)
```

Подтверждено на Debian 12 + Ubuntu 24.04: foreign stock remains, FIC
identifier исчезает, password change работает, weak reject работает.

### История harness failures v4–v7 (почему ранние FAIL нельзя использовать против C2)

- v4: `chpasswd` давал failures даже со stock pwquality -> verdict
  UNKNOWN, не доказательство против C.
- v5: собственный `pam_chauthtok()` helper; parser терял RESULT records
  (harness bug).
- v6: framing исправлен, но C helper печатал literal `\n` и отсутствовал
  cracklib runtime dictionary (`/var/cache/cracklib/cracklib_dict.pwd`) —
  environment incompleteness делала невалидным даже stock oracle.
- v7: после исправления helper output, parser и добавления cracklib
  runtime/dictionary + fail-fast environment validation stock oracle стал
  `strong=true / weak=true / overall=true`, и вся C2 matrix зелёная на
  Debian 12 + Ubuntu 24.04.

## DECISION

```text
Use C/C2 activation-time FIC-owned PAM profiles.
```

Отвергнуто: permanently selected high-priority neutral password hook
(опровергнуто gate'ом).

Package устанавливает definitions/slots, но password profiles не обязаны
быть selected, пока соответствующая runtime policy не активна.

Ownership:

```text
package:            owns profile definitions + managed slot files
runtime policy:     decides which FIC-owned profile identifiers are selected
pam-auth-update:    exclusively owns generated common-password
journal/provenance: records only FIC-owned runtime mutations
foreign profiles:   never implicitly become FIC-owned
```

## Implemented (этот шаг): model + planner + payload groundwork

### Topology model (`PamPasswordTopologyModel.{h,cpp}`, pure)

- `PamPasswordProducerKind`: None / FicQuality / FicHistoryInitial /
  ForeignQuality.
- `PamPasswordHistoryKind`: None / FicConsumer.
- `PamPasswordSelections` (физические selections) отделены от
  `PamPasswordOwnership` (journal provenance) — физическая selection и
  FIC-ownership суть разные вещи.
- `PamPasswordTopology` + coarse `PamPasswordTopologyClass`: None,
  FicQuality, FicHistoryInitial, FicQualityPlusFicHistory, ForeignQuality,
  ForeignQualityPlusFicHistory, ForeignQualityPlusFicQuality
  (foreign-added-during-FIC; distinguishable, НЕ valid), Ambiguous
  (обе history-варианты, foreign+initial, semantic/selection
  несовпадение — fail closed).
- `classifyPamPasswordTopology()` — typed classification с fail-closed
  на ambiguous/incoherent.
- `evaluatePamPasswordC2SelectionSafety()` — структурная C2-безопасность
  selections x slot states x foreign producer (validator groundwork):

```text
quality selected         -> quality slot MUST be Active
                            (selected + Neutral = UNSAFE)
history-initial selected -> initial slot Active AND consumer NOT selected
history consumer selected-> history slot Active AND producer exists
                            (FIC quality Active ИЛИ foreign quality)
ничего не selected       -> все slots Neutral
                            (Active без профиля = orphaned, fail closed)
Broken/Unavailable       -> всегда unsafe (existence invariant)
```

Новый C2-инвариант Neutral: comment-only Neutral bytes безопасны ТОЛЬКО
потому, что соответствующий activation profile обязан быть unselected, пока
Neutral. Provenance (MatchingApplied, mutation ids) остаётся за read-only
attach validator'ом поверх этой классификации.

### Pure planner (`PamPasswordTopologyPlanner.{h,cpp}`)

`planPamPasswordTopology(current, qualityRequested, historyRequested,
ownership)` — без filesystem/pam-auth-update mutation. Возвращает desired
selections (`wantFicQuality` / `wantFicHistoryInitial` /
`wantFicHistoryConsumer`) + ordered semantic actions
(`PamPasswordPlanActionKind`: Attach/Detach x Quality/HistoryInitial/
HistoryConsumer).

Rules: Q=true -> FIC quality только при отсутствии foreign producer;
H=true с producer в desired state -> consumer; H=true без producer ->
initial producer; Q+H без producer -> quality + consumer (никогда
initial); disable -> detach только FIC-OWNED selections, foreign никогда
не трогается; selected-but-unowned не detach'ится (fail closed), а
unowned-but-kept репортится в `unownedSelectionsPreserved`.

Порядок действий: detaches — consumer до producer; attaches — producer до
consumer. Transition variant switching реализован явно: Q+H -> H-only =
consumer->initial (P10), H-only -> Q+H = initial->quality+consumer (P11).
Unit-тесты: `pam_password_topology_planner_tests` — полная матрица P1–P12
+ ownership-aware disable + foreign-during-H + disable-all.

### Payload (три FIC activation identity)

```text
packaging/deb/pam-configs/fic-password-quality-hook           Priority: 1024
    Password и Password-Initial -> include fic-password-quality
packaging/deb/pam-configs/fic-password-history-hook           Priority: 1023
    Password и Password-Initial -> include fic-password-history (consumer)
packaging/deb/pam-configs/fic-password-history-initial-hook   Priority: 1022
    Password и Password-Initial -> include fic-password-history-initial
```

- Все три: `Default: no`, `Password-Type: Primary`, password-facility only.
- Initial и consumer — ДВА явных FIC-owned topology варианта;
  Password-Initial switching одного history profile больше не
  используется. Consumer mirroring'ит include в Password-Initial: во
  всяком ВАЛИДНОМ C2 состоянии consumer никогда не находится на modpos 0
  (выше него всегда producer: FIC quality 1024 или stock pwquality),
  поэтому Password-Initial consumer никогда не выигрывает; пустая секция
  имела бы недоказанную pam-auth-update семантику.
- Priorities rationale: 1024/1023 — v7-verified значения
  (ficQ < ficH < unix). Stock unix = 256 (Debian/Ubuntu). Initial = 1022:
  валидное окно (256, 1023), никогда не co-selected с consumer, поэтому
  единственное требование — producer-позиция до pam_unix; 1022 выбрано
  детерминированно. Foreign stock pwquality на Debian/Ubuntu сортируется
  раньше FIC consumer (v7: stock pwquality раньше fic-password-history);
  priority-отношения FIC<->foreign валидируются attached-фазой (Rule G:
  producer до history include в effective stack), а не payload-константой.
- Managed slot paths не изменились (три conffile, canonical neutral body
  `# FIC managed password slot: state=neutral` + LF`).
- `install_fic_pam_profiles` stage'ит третий профиль; conffiles unchanged;
  postinst по-прежнему НЕ активирует ни один password-профиль
  (bootstrap -> validate -> faillock only). Package install остаётся safe.

### Prerm (минимальное изменение) и audit assumptions, invalidated C2

Минимальные правки под третий профиль: snapshot
`fic_password_history_initial_hook_selected` + третий профиль в
`pam-auth-update --package --remove` списке. Proof-функция
`fic_prove_password_hook_state_restored` обновлена под C2
consumer-идентичность (history-hook proof = ровно один
fic-password-history include; initial include остался только как
absence-guard).

Assumptions, invalidated C2 и требующие редизайна ДО runtime activation /
package-removal integration:

- permanent password selection (gate-модель) — отвергнута;
- two-profile model (quality + dual-include history) — заменена тремя
  identity;
- proof/restore НЕ знают про initial hook (нет restore-ветки, нет
  positive proof): failed-removal recovery не восстановит pre-removal
  selected initial hook (fail-closed путь, exit 1, но restore неполный);
- `fic_prove_password_hook_state_restored` — two-arg grammar, нужна
  three-profile переработка вместе с executor'ом;
- prerm snapshot/restore произвольных selected password hooks —
  двухпрофильная логика;
- fake pam-auth-update grammar в `PamPackagingChecks.py` — обновлён под
  C2 single-identity profiles, но не моделирует selection initial hook;
- trailing-whitespace дефект реальной генерации (trailing space в
  include-строках) в prerm proof остаётся (см. ниже).

## pam-auth-update grammar notes (из gate + Step 5B, всё ещё актуально)

- Include-строки package-профилей имеют TRAILING SPACE — anchored `$`-proofs
  без `[[:space:]]` никогда не сходятся с реальной генерацией. Prerm proof
  всё ещё использует anchored `$` (latent defect, чинить вместе с
  executor-редизайном prerm).
- Password-Initial вариант профиля используется только для модуля на
  modpos 0 Primary блока.

## C2 REAL functional gates (этот шаг, docker, disposable, root)

Харнес: `tests/integration/pam-c2/pam_c2_gate.sh` +
`pam_c2_gate_driver.cpp` (production-компоненты: bootstrap, inspect,
transition через `VerifiedProcessExecutor` + реальный pam-auth-update) +
`fic_pam_probe.c` (setuid-root probe, исполняется AS gate user —
`getuid() != 0`, поэтому pam_pwhistory/pam_pwquality enforce; модель
passwd(1)). Payload — exact `packaging/deb/pam-configs/fic-*` профили.
Evidence: `/tmp/gate-ev-deb12`, `/tmp/gate-ev-u2404` (common-password,
slots, /var/lib/pam/password, journal, pam-auth-update invocation log,
shadow digest'ы; реальные пароли не сохраняются).

Уроки среды (зафиксировать в harness-инварианты):

- `libpam-pwhistory` не существует — pam_pwhistory в libpam-modules.
- pwquality/pwhistory по умолчанию НЕ enforce для root: нужен
  `enforce_for_root` (pwquality.conf) и запуск probe от пользователя
  (setuid-модель) — иначе даже stock oracle невалиден.
- Пароли gate не должны содержать имя пользователя (pwquality
  usercheck).
- Debian 12/Ubuntu 24.04 (Linux-PAM 1.5.x): `enforce_for_root` для
  pam_pwhistory НЕ поддерживается (появился в 1.6.x) — потому
  self-change probe обязателен.
- Native failure injection — через wrapper `/usr/sbin/pam-auth-update`
  (лог + one-failure flag), тот же wrapper доказывает G10
  (one-profile-per-invocation, $# == 2).

### Debian 12 (bookworm)

| Gate | Verdict |
| --- | --- |
| G1 None baseline | PASS |
| G2 None→Quality (+disable) | PASS |
| G3 None→History-only (+disable, reuse reject) | PASS |
| G4 None→Q+H (strong/weak/reuse) | PASS |
| G5 Q+H→H-only (detach consumer, detach quality, attach initial) | PASS |
| G6 H-only→Q+H | PASS |
| G7 Foreign stock pwquality pre-existing | PASS |
| G8 Foreign added during FIC (FIC-only removal, stock-only structural match) | PASS |
| G9 Trailing-whitespace grammar (реальная генерация принята proof'ом) | PASS |
| G10 One-profile-per-invocation | PASS |
| G11 Real native failure probe (injected pam-auth-update failure → compensation → working path → recovery) | PASS |

C2 REAL FUNCTIONAL GATE: PASS.

### Ubuntu 24.04.5 LTS

| Gate | Verdict |
| --- | --- |
| G1 | PASS |
| G2 | PASS |
| G3 | PASS |
| G4 | PASS |
| G5 | PASS |
| G6 | PASS |
| G7 | PASS |
| G8 | PASS |
| G9 | PASS |
| G10 | PASS |
| G11 | PASS |

C2 REAL FUNCTIONAL GATE: PASS.

## Completed (этот шаг)

- Substage 1: ReadOnly lift (Debian 12 + Ubuntu 24.04) + support contract
  tests.
- Substage 2: `PamPasswordTopologyCoordinator` + joint policy mode +
  daemon wiring (apply, startup reconcile, idempotence, foreign
  satisfaction).
- Substage 3: C2 rollback integration (`rollbackPolicyBeforeDisable` →
  `undoPamCapability` → joint transition), без изменения schema journal.
- Substage 4: wiring E2E тесты R1-R16 + failure/unsafe/foreign матрица;
  real wiring gates Debian 12 + Ubuntu 24.04.

## Changed areas

- `fic/src/platform`: PlatformProfile.h (новый флаг),
  profiles/{Debian12,Ubuntu2404}Profile.cpp.
- `fic/src/modules/identity_access/pam`: PamPasswordTopologyCoordinator.*
  (новый), PamProviderCatalog.cpp,
  policies/PamCapabilityActivationPolicy.{h,cpp}.
- `fic/src/rollback`: PamRollback.{h,cpp}, RollbackExecutor.{h,cpp},
  IdentityAccessPolicy.h (public mutex accessor).
- `fic/src/daemon/main_function.cpp` (activation + rollback wiring).
- `tests/`: PamPasswordWiringTests.cpp (новый, 21 тест), CMake-таргеты
  (pam_password_wiring_tests, fic-pam-c2-wiring-driver), обновлённые
  legacy-кейсы PamCapabilityActivationPolicyTests (password capabilities
  больше не идут через legacy manager path), integration gate
  pam_c2_wiring_gate.sh + pam_c2_wiring_driver.cpp (новые),
  fic_pam_probe.c (детерминированная текстовая маршрутизация промптов
  current/new вместо first-prompt эвристики — behavior-preserving для
  executor-гейта, см. Validation).

## Validation (этот шаг, фактически выполнено)

- Build: `cmake -S . -B build-runtime-wire -DFIC_TARGET_PLATFORM=ubuntu-24.04
  -DBUILD_TESTING=ON` + full build — OK; debian-12 и debian-13 конфигурации
  собраны, wiring-тесты зелёные на всех трёх.
- CI follow-up для run `36237012929`: synthetic pwquality fixture в
  `passwdqc_config_file_tests` теперь явно проверяет обе стороны нового
  evidence-gated контракта: без `passwordTopologyRuntimeMutable` —
  `ReadOnly`, с поднятым флагом — `RequiresTopologyActivation`.
- В checkout `/home/admsys/FIC`: fresh configure
  `/tmp/fic-home-ci-36237012929-fix`, сборка targets
  `passwdqc_config_file_tests` и `pam_password_wiring_tests`, затем оба
  теста — успешно; `git diff --check` — clean.
- `pam_password_wiring_tests`: 21/21 PASS (R1-R16 apply/rollback/restart,
  rollback failure fail-closed, selected-but-unowned, unsafe state,
  policy-level joint intent, support contract) на ubuntu-24.04, debian-12
  (lift подтверждён) и debian-13 (ReadOnly подтверждён).
- `git diff --check` — clean. Static scan: pam-auth-update упоминается
  только в executor/writer (+комментарии); common-password не редактируется
  вне C2 writer stack; ReadOnly снят только на целевых платформах;
  mutable-флаг не включён на неподдерживаемых.
- **Real wiring gates** (`tests/integration/pam-c2/pam_c2_wiring_gate.sh`
  в disposable docker-контейнерах as root, драйвер через PRODUCTION
  coordinator API): **Debian 12 — W1-W9 PASS**,
  **Ubuntu 24.04 — W1-W9 PASS** (C2 PRODUCTION WIRING GATE: PASS на обеих;
  evidence /tmp/wg-deb12, /tmp/wg-u2404 на хосте).
- Executor-level gates G1-G11 (`pam_c2_gate.sh`) перезапущены после фикса
  executor'а и probe'а: **Debian 12 — PASS, Ubuntu 24.04 — PASS**
  (evidence /tmp/eg-deb12b, /tmp/eg-u2404). Единственный сбой первого
  прогона deb12 — G11 "strong change failed after recovery" — тот же
  flaky hex-генератор паролей executor-гейта против cracklib; генератор
  заменён на проверенный base64-вариант (probe text-routing
  behavior-preserving).
- Harness lessons (wiring gate): Debian 12 pwquality default minlen=8 —
  'weakpass' (8 lowercase) ПРОХОДИТ (использовать 'password1', как в
  executor-гейте); генератор strong-паролей — random base64-средник
  (hex-суффикс flaky против cracklib); probe маршрутизирует промпты по
  тексту (current/old vs new); reuse-проверка истории возможна только
  после успешного изменения ПОД pwhistory (pre-FIC пароль в opasswd не
  попадает); distro-контейнеры могут автoselect stock pwquality при
  установке libpam-pwquality — гейт нормализует baseline.
- Executor-гейт и wiring-гейт используют разные evidence dir, но ОБА
  оборачивают /usr/sbin/pam-auth-update wrapper'ом — в ОДНОМ контейнере
  их не запускать.
- Executor-level gates G1-G11 (предыдущий шаг) — по-прежнему PASS на
  обеих платформах (baseline).

## Explicitly NOT done (scope boundary этого шага)

- Three-profile prerm redesign; удаление временного prerm preflight.
- Step 6 ModuleArguments option writer — pwhistory module arguments в
  слотах сейчас фиксированы на wiring call sites ({remember=3,
  enforce_for_root=false}); depth/enforce как policy values — следующий
  этап.
- Прямое редактирование /etc/pam.d/common-password — НЕ появилось.
- Новый topology planner — НЕ создавался (planner остаётся единственным
  semantic source).

## Remaining

1. **Three-profile prerm redesign**: снимает preflight и Temporary
   invariant ниже; trailing-whitespace уже решён на C++-стороне — prerm
   proof либо идёт через maintenance CLI (один source of truth), либо
   чинит anchored-`$` грамматику в shell.
2. **Step 6 ModuleArguments option writer** (см. Explicitly NOT done).
3. Broader distro gates (Debian 13 / Ubuntu 26.04) если требуются — их
   платформы остаются ReadOnly до прохождения gates.
4. Заметки среды: proxy в docker-контейнерах нестабилен (apt retries
   в gate harness); не запускать параллельно /tmp-конфликтующие test-наборы
   (wiring gate использует СВОЙ evidence dir
   /tmp/fic-wiring-gate-evidence, но /usr/sbin/pam-auth-update wrapper —
   общий: executor-гейт и wiring-гейт не запускать в одном контейнере
   одновременно).
