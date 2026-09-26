# FIC: передача контекста

## Current base

- Ветка `main`. Baseline: `068b6338c491cae8e6ec3f62b0d7def00ed2fb10`
  ("Follow-up к последнему коммиту") — C2 runtime transition executor
  (999505d) + follow-up fix attach partial-state propagation (F11)
  ЗАКОММИЧЕНЫ.
- Поверх baseline выполнен **F12 hardening** (uncommitted, commit не
  запрошен) + real functional gates G1–G11 на Debian 12 и Ubuntu 24.04
  (см. ниже).

### C2 attach partial-state propagation fix (этот шаг)

- Writer контракт `PamManagedPasswordSlotActivationResult.mutationId`
  (формализован в комментарии): на failure nonzero ТОЛЬКО когда exact
  outstanding C2 activation остаётся физически/journal-present и требует
  caller-side compensation через `compensateC2ActiveSlot()`; при полной
  внутренней компенсации writer'а (exact restore + Prepared discard) — 0.
  Это НЕ historical "id once allocated".
- `PamManagedPasswordSlotWriter::activateC2Slot()`: ветка
  `completePrepared(id)` failure теперь выставляет
  `result.mutationId = id` (при сохранённом honest
  `changedSystemState = true`); `compensateFreshFailure()` при
  неудавшемся внутреннем restore тоже пропагирует id (Active exact-id
  slot + Prepared остаются caller-compensatable). Ветви render/write/proof
  с успешной внутренней компенсацией остаются с mutationId == 0 —
  executor не пытается neutralize уже Neutral slot (нет двойной
  compensation).
- `PamPasswordTopologyTransitionExecutor::executeAction()` (attach):
  `attempt.slotMutationId = activation.mutationId` копируется НЕЗАВИСИМО
  от bool return'а `activateC2Slot()` (раньше — только после success, из-
  за чего failure после physical write оставлял Active slot + Prepared
  record без компенсации).
- Test seam: `setJournalCompletionFaultHookForTests` (writer) +
  passthrough'ы executor'а — инжект failure journal
  Prepared→Applied commit после успешной физической записи; production
  никогда hook не ставит.
- Тесты: **F11** `journalCompletionFailsAfterSlotWrite` (None → Quality,
  fault = completePrepared; expects: failure, native invocations == 0,
  compensated + compensatedStateProven, slot Neutral, Prepared record
  discarded, no Applied ownership, topology == None, diagnostic БЕЗ
  "NOT proven restored"); writer-тесты **W-C2** (failure после записи →
  changedSystemState=true, mutationId=exact id, record Prepared, затем
  успешная exact-id caller compensation) и **W-C2-clean** (внутренне
  полностью скомпенсированный failure → mutationId=0, no physical
  change). F11 проверен на воспроизведение бага: без executor-фикса
  тест падает с "C2 PAM topology NOT proven restored".

### F12 compensation-of-compensation hardening (этот шаг, uncommitted)

- Проблема: detach-inverse compensation (`compensateAttempt`, ветка
  re-attach) при `activateC2Slot() == false` просто делала
  `return false` — при partial path (slot write persisted, fresh proof
  OK, Prepared→Applied commit FAIL) это оставляло НОВЫЙ orphaned
  Active slot + Prepared record поверх несостоявшегося восстановления.
- Fix: в detach-inverse при неудаче активации executor различает
  Case A (`mutationId == 0` — writer полностью скомпенсировал внутри,
  fail-fast без cleanup) и Case B (`mutationId != 0` — exact-id локальный
  cleanup через `compensateC2ActiveSlot()` ДО fail-fast STOP, без
  рекурсивного compensation engine). Диагностик различает
  "its partial slot activation was cleaned" vs "could NOT be cleaned".
- Test seam: `setC2CompensationFaultHookForTests` (writer,
  `!hook()` → fail в начале `compensateC2ActiveSlot`) + passthrough
  `setHistoryC2CompensationFaultHookForTests` (executor); production
  никогда hook не ставит. Внимание: `deactivateC2Slot()` ВНУТРЕННЕ
  вызывает `compensateC2ActiveSlot()` — hook нельзя ставить до начала
  compensation (F12b ставит его в момент неудачного native disable).
- Тесты: **F12** (Q+H→None; второй disable падает; compensation
  re-attach consumer'а ломается completion fault'ом → exact cleanup →
  STOP: transition false, compensated, "NOT proven restored" +
  "partial slot activation was cleaned", history slot Neutral, no
  Prepared, appliedCount==1, ровно 4 native invocation'а) и **F12b**
  (cleanup сам падает → честный остаток: Active slot + Prepared record +
  "could NOT be cleaned"). Без фикса F12 падает (проверено).

## Current task

C2 runtime transition executor + three-profile resulting-state proof +
partial-failure compensation — реализовано как production runtime layer:

- `PamPasswordTopologyState.{h,cpp}` (новый): production read-only typed
  snapshot — selections из state-файла (`Module:` records), три managed
  slot states, generated-stack evidence (`common-password`) с
  trailing-whitespace-толерантной грамматикой, foreign producer discovery
  (Rule I: stock `pwquality` profile XOR direct `pam_pwquality.so` rule —
  несогласованность = coherence error), ownership per identity (payload
  contract writer'а: Applied + role-specific activation identifier),
  семантическая модель + `classifyPamPasswordTopology` +
  `evaluatePamPasswordC2SelectionSafety`; плюс
  `provePamPasswordTopologySemantics` — three-profile proof с effective
  ordering (producer < history consumer < pam_unix; initial < pam_unix;
  foreign producer < history).
- `PamManagedPasswordSlotWriter`: C2 per-identity lifecycle (public):
  `proveOwnedC2Slot(role)`, `activateC2Slot(role)` (Prepared → write →
  fresh proof → Applied; idempotent; exact crash-partial Prepared
  adoption), `deactivateC2Slot(role)` (Applied-owned → CAS-neutralize →
  fresh Neutral → RolledBack), `compensateC2ActiveSlot(id)` (exact-id;
  Applied → RolledBack, Prepared → discard; foreign-id/Neutral fail
  closed). Payload record'а несёт ROLE-SPECIFIC activation identifier
  (quality/history/history-initial hook).
- `PamPasswordTopologyTransitionExecutor.{h,cpp}` (новый): transition =
  inspect → validate → `planPamPasswordTopology` (planner — единственный
  semantic decision source) → no-op fresh desired proof → per action:
  drift gate → slot mutation (attach: Active slot FIRST; detach:
  selection removal FIRST) → ровно ОДИН профиль на pam-auth-update
  invocation → immediate fresh resulting-state proof → финальный полный
  proof → success. Failure → semantic-inverse compensation (reverse of
  proven mutations + pending attempt), fail-fast ("C2 PAM topology NOT
  proven restored"), foreign drift aborts the stale plan (one plan per
  transition), foreign preserved, selected-but-unowned никогда не
  мутируется. rc native никогда не доверяется: rc=0 + malformed =
  failure, rc!=0 + exactly proven = ok.
- Тесты `PamPasswordTopologyTransitionExecutorTests.cpp` (target
  `pam_password_topology_executor_tests`): fake native mutator (fake
  /var/lib/pam + /etc/pam.d, trailing-space grammar,
  one-profile-per-invocation assertion) — E1–E12 (все success
  transitions, включая variant switching Q+H↔H-only, foreign
  pre-existing no-op, foreign+H, foreign-added-during-FIC disable) и
  F1–F10 (failure matrix).

## Accepted architecture / invariants

- Physical selection != FIC ownership; detach только journal-proven
  FIC-owned identities; foreign producer никогда не claimed/removed.
- Attach ordering: Active slot → proof → selection. Detach — обратный.
- `changedSystemState` monotonic/honest; Prepared/Applied lifecycle per
  slot activation (existing MutationJournal semantics, без изменения
  schema); common-password никогда не копируется/не snapshot'ится.
- **`PamPolicySupport::ReadOnly` для password capabilities СОЗНАТЕЛЬНО
  НЕ поднят**: executor/proof/compensation proven на unit-уровне И
  real functional gates G1–G11 прошли на Debian 12 + Ubuntu 24.04 —
  lift разрешён, следующий отдельный этап (§ Remaining).
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

## Validation (этот шаг, фактически выполнено)

- `cmake --build build-c2 -j4` — OK; targeted ctest
  `pam_password_topology_executor|pam_managed_password` — 4/4 PASS;
  executor tests **25/25** (E1–E12, F1–F12 + F12b).
- Full CTest: только известный baseline failure
  `passwdqc_config_file_tests` (вне scope) + 1 skip; `git diff --check`
  — clean.
- **Real functional gates** (`tests/integration/pam-c2/pam_c2_gate.sh`
  в disposable docker-контейнерах as root; evidence в `/tmp/gate-ev-deb12`
  и `/tmp/gate-ev-u2404`): **Debian 12 — G1–G11 PASS**,
  **Ubuntu 24.04.5 — G1–G11 PASS**, stock pwquality oracle PASS на
  обеих. C2 REAL FUNCTIONAL GATE: PASS.
- Debian 12 build/CTest и packaging checks — НЕ выполнялись в этом шаге
  (gate собирал только gate-driver target внутри контейнеров).

## Explicitly NOT implemented (scope boundary этого шага)

- ReadOnly lift + daemon/runtime policy wiring + rollback integration
  (PamRollback deactivateC2Slot путь).
- Three-profile prerm redesign; maintenance CLI (`fic --maintenance
  inspect-pam-password-topology` — candidate).
- Step 6 (Debian 12 ModuleArguments option writer) — не требовался
  механике executor'а; canonical writer behavior использован как есть.
- Functional gates на реальных Debian 12 / Ubuntu 24.04 — ВЫПОЛНЕНЫ
  (этот шаг, см. таблицы выше).

## Remaining

1. **ReadOnly lift + daemon wiring** (gates пройдены — разрешено):
   `pamPolicySupport` → RequiresTopologyActivation для password
   capabilities на PamAuthUpdate platforms; password activation policy
   поверх executor'а (joint Q/H request: чужая capability выводится из
   физического состояния — selected или foreign producer); rollback
   интеграция.
2. **Three-profile prerm redesign**: снимает preflight и Temporary
   invariant; trailing-whitespace уже решён на C++-стороне — prerm proof
   либо идёт через maintenance CLI (один source of truth), либо чинит
   anchored-`$` грамматику в shell.
3. Step 6 ModuleArguments option writer; Step 7 activation.
4. Заметки среды: proxy в docker-контейнерах нестабилен (apt retries
   в gate harness); baseline failure `passwdqc_config_file_tests` — вне
   scope; не запускать параллельно /tmp-конфликтующие test-наборы.
