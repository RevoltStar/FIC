# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `b826359`; рабочее дерево содержит правку только
  `docs/HANDOFF.md` (docs-only Step 1 design closure).

## Current task

- Docs-only design closure Step 1 (PasswordQuality/PasswordHistory managed
  topology): закрыты архитектурные блокеры A/B/C/G/I/J с behavioral
  доказательствами (fixture v3). Production-код, тесты, packaging НЕ
  менялись. Step 2 РАЗБЛОКИРОВАН (см. Remaining).

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

## Completed

- Step 1 design closure (docs-only): fixture v3 behavioral proofs
  (neutral candidates, history-behind-include, FIC-producer, external +
  FIC history, history-only, lifecycle enable/disable/enable); выбор
  Candidate 1; решения A/B/C/G/I/J = RESOLVED; decision matrix;
  уточнения D/E/F/H. Production-код, тесты, packaging НЕ менялись.
- Ранее (v2): pam-auth-update mechanics без `--force` на 4 платформах,
  placement/tie-break proof, инварианты packaging flow.

## Changed areas

- `docs/HANDOFF.md` (единственный изменённый файл; scratch-артефакты —
  `/tmp/pam-gate-v3/`, вне репозитория).

## Validation

- Docker fixture v3 (podman-backed docker CLI, контейнеры `--rm`,
  debian:12 + ubuntu:24.04; методика и ограничения описаны выше в
  «Fixture evidence v3»): r0 (debug), r1-neutral ×2 платформы, r2-ficq,
  r3-pos0, r4-extqh ×2 платформы, r5-historyonly, lifecycle probe в
  постоянном контейнере (удалён после теста). Все PASS (= наблюдаемое
  поведение получено и задокументировано).
- Интерактивный `passwd(1)` в контейнере — недостоверён (артефакт
  pty-агрегации `script`), вынесен в staging (Step 4+).
- `git diff --check` — чисто; production-код/тесты/packaging не
  затронуты.

## Remaining

- Step 1 ЗАКРЫТ (A/B/C/G/I/J = RESOLVED, decision matrix заполнена).
  К Step 2 можно переходить.
- Step 2: password slot topology + marker parsing в
  `fic/src/modules/identity_access/pam/` (модель
  `PamAuthUpdateTopologyManager`/faillock slots).
- Step 3: journal-bound ownership + marker parser (контракт D выше).
- Step 4: `PamSlotAttachValidator` (правила G/I: token-producer перед
  history, single pam_pwquality provider; external-compliant
  detection) + интерактивная passwd-валидация на staging.
- Step 5: packaging (`packaging/deb/`: hook-профили + slot targets;
  extend permanent-hook proof на password hooks; конffile registration
  всех трёх slot).
- Step 6: Debian 12 module-argument writer (по J).
- Step 7: lift `PamPolicySupport::ReadOnly` →
  `RequiresTopologyActivation`; удалить
  `legacyPamAuthUpdatePasswordTopology` bypass последним.
- Step 8: обязательные тесты (PamCapabilityActivationPolicyTests,
  PamAuthUpdateTopologyManagerTests, PamSlotAttachValidatorTests,
  PamOptionPolicy/pwhistory argument tests, PlatformProfileTests,
  RollbackExecutorTests, PamPackagingChecks).
- Step 9: docs (авторитетное описание password slots — расширение
  `docs/pam-owned-faillock-slots.md`).
- Infra: docker CLI = podman (user socket
  `/run/user/<uid>/podman/podman.sock`; при ошибке подключения —
  `systemctl --user start podman.socket` и/или экспорт `DOCKER_HOST`).
  Daemon инжектит сломанный proxy env во все контейнеры — на `docker
  run` добавлять `--env http_proxy= --env https_proxy= --env
  HTTP_PROXY= --env HTTPS_PROXY=` (или unset перед вызовом).
