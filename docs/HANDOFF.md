# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `b72a56368e62040dde73caee18e731e119befab2`,
  рабочее дерево содержит правку только `docs/HANDOFF.md`.

## Current task

- Docs-only follow-up Step 1 (PasswordQuality/PasswordHistory managed
  topology): исправление design gate. Production-код не менялся.
  Fixture v2 повторены production-like flow БЕЗ `--force`
  (`/tmp/pam-gate-v2/`, вне репозитория). Ниже: точный placement proof,
  fixture v2 результаты, оригинальный checkpoint A–J со статусами
  RESOLVED/UNRESOLVED, инварианты. Итог: Step 1 ЗАКРЫТ НЕ ПОЛНОСТЬЮ —
  есть блокеры (см. Remaining); к Step 2 не переходить.

### Placement proof (точная форма, fixture v2)

- Distro `pwquality` Priority = 1024; `unix` Priority = 256; FIC
  quality hook Priority = 1024; FIC history hook Priority = 1023.
- Авторитетный tie-break (`/usr/sbin/pam-auth-update`):
  `sort { Priority DESC || $b cmp $a }` — при равном приоритете профиль
  с бо́льшим именем (лексикографически) выше. Поэтому при равных 1024
  порядок: `pwquality` (P) → `fic-password-quality-hook` (Q).
- Сортировка выполняется дважды: над всеми профилями и над enabled
  набором, поэтому placement стабилен между `--package` и `--enable`.
- Результат на всех четырёх платформах (debian:12, debian:13,
  ubuntu:24.04, ubuntu:26.04), hook-профили dual-stack
  (`Password` + `Password-Initial`), flow = `--package` + отдельные
  `--enable`, БЕЗ `--force`:

```text
password requisite           pam_pwquality.so retry=3
password include             fic-password-quality   [FIC quality hook, 1024]
password include             fic-password-history   [FIC history hook, 1023]
password [success=1 ...]     pam_unix.so obscure use_authtok try_first_pass yescrypt
```

- unix на позиции 1 → обычный вариант с `use_authtok`; на позиции 0 →
  Initial-вариант без него.
- ВАЖНО (связь с пунктом I): quality hook в этом дизайне — ТОЛЬКО
  include-обёртка (маркер + include managed slot-файла), а НЕ второй
  провайдер `pam_pwquality.so`; дублирование провайдера исключается
  только правилами заполнения managed slot (см. I ниже).

### Design checkpoint A–J (оригинальные вопросы; статусы по fixture v2)

```text
A. Какая permanent hook topology выбрана?
B. Какие managed password slots существуют?
C. Как выглядит neutral state?
D. Как active state хранит mutation id?
E. Как обеспечивается password-Initial?
F. Где появляется password token?
G. Почему use_authtok находится в правильном месте?
H. Как quality/history взаимодействуют друг с другом?
I. Как external distro pwquality остаётся external?
J. Где Debian 12 pwhistory option policies делают запись?
```

- **A — UNRESOLVED (блокер Step 2)**. Доказанные строительные блоки:
  hook-профили (`Password-Type: Primary`, `include` managed slot target,
  Priority 1024/1023) с гарантированным placement (tie-break
  `Priority DESC || $b cmp $a`). Кандидаты topology (не выбрано):
  1. per-capability пары hook-профилей (quality/history отдельно);
  2. единый password hook-профиль с двумя include;
  3. только history hook, quality остаётся на дистро-профиле.
  Требуется фикс-решение в терминах: selected profile X → generated
  password include Y → managed file Z, отдельно для quality/history.
  Step 2 нельзя начинать с невыбранной topology.
- **B — UNRESOLVED (блокер Step 2)**. Рабочая гипотеза (не утверждена):
  conffile-слоты `/etc/pam.d/fic-password-quality` и
  `/etc/pam.d/fic-password-history` (+ параллельный
  `/etc/pam.d/fic-password-history-initial` для Initial-варианта),
  по модели faillock slots. Требуется: полный список файлов, владелец
  каждого, поведение при partial admin edits. Абстрактные «slot-файлы»
  без точного набора — не ответ.
- **C — UNRESOLVED (блокер Step 2; behavioral данные есть)**.
  `auth optional pam_deny.so` из faillock механически НЕ переносится:
  password stack имеет другую семантику. Кандидат (проверен
  behavioral в r5, но не утверждён как canonical):
  `password required pam_permit.so` — не создаёт prompt, не ломает
  token acquisition, не является allow-path, безопасен при деградации
  include-topology. Требуется зафиксировать canonical neutral body для
  quality и history отдельно, включая случай slot-файл первый в стеке.
- **D — UNRESOLVED (блокер Step 3)**. Формат active state не выбран.
  Минимальные требования: capability identifier, slot identifier,
  mutation id (монотонный), version, exact-body ownership, canonical
  BEGIN/END маркеры либо иной ownership grammar. Каркас-пример (НЕ
  production-формат):
  `#@FIC_PAM_SLOT_BEGIN version=1 capability=... mutation=... slot=...`
  ... `#@FIC_PAM_SLOT_END version=1 capability=... mutation=... slot=...`.
  Грамматики quality/history могут отличаться. Journal binding — как в
  faillock (`journalBindsPhysicalOwnership`).
- **E — PARTIALLY RESOLVED**: семантика доказана (`<Type>-Initial`
  выбирается только для профиля на позиции 0; r1/r2/r6). Physical
  design НЕ выбран: slot-пара (обычный + `-initial` include target)
  либо гарантия «never first» (связать с A и G). «pam-auth-update сам
  разберётся» — НЕ ответ: module rule находится внутри FIC managed
  include file.
- **F — PARTIALLY RESOLVED**: для intended placement (history hook
  после quality-провайдера, до pam_unix): token producer —
  pam_pwquality (или pam_unix при отсутствии pwquality) → pam_pwhistory
  потребляет через use_authtok → pam_unix final provider. Behavioral
  подтверждено (r5: rejection повторов при remember=2, opasswd).
  Для history-only топологии producer НЕ доказан (r6) — см. G.
  Отдельно решить: если FIC quality disabled и дистро pwquality
  отсутствует — кто producer для history.
- **G — PARTIALLY RESOLVED**: `use_authtok` корректен, только если до
  pwhistory в стеке есть token producer. Доказано: history hook МОЖЕТ
  оказаться первым (r6), и тогда enforcement не соответствует intended.
  Проектное требование: intended topology гарантирует «pwhistory не
  первый password-модуль» (приоритеты дают это, пока существует дистро
  pwquality или FIC quality hook; админ может их убрать) — нужен либо
  pre-attach validator rejection, либо явный Unsupported-статус.
  Блокер для Step 2.
- **H — PARTIALLY RESOLVED**. Матрица состояний (утвердить в Step 2):
  * external quality + history off — допустимо; token producer — дистро
    pwquality; baseline;
  * external quality + FIC history — допустимо, intended основной кейс
    Debian/Ubuntu; FIC hook = include-only, НЕ второй провайдер;
  * FIC quality + history off — только если внешнего провайдера нет
    (иначе duplicate `pam_pwquality.so`); правило детекции «external
    отсутствует» не сформулировано;
  * FIC quality + FIC history — как выше плюс FIC history;
  * quality absent + FIC history — требует решения по G (history без
    producer) и по I (нужен ли FIC quality topology вообще).
  Определения: «external» = selected дистро `pwquality` профиль в
  `/var/lib/pam/password`; «FIC-owned» = FIC hook профиль selected +
  marker/journal ownership в managed slot.

- **I — UNRESOLVED (требует явной архитектурной формулировки)**.
  Инвариант зафиксирован: selected/active дистро `pwquality` НИКОГДА
  не становится FIC-owned только потому, что capability structurally
  effective; FIC не отключает, не заменяет и не создаёт journal
  ownership поверх него; FIC option policies продолжают управлять
  `/etc/security/pwquality.conf` в текущих semantics
  (`PwqualityConfigFile` + semantic verifier provider/config path).
  Открытый вопрос: нужен ли вообще отдельный FIC quality topology при
  активном дистро pwquality. Рабочая гипотеза: «external pwquality
  удовлетворяет topology → enable_password_quality effective-but-
  non-owned; FIC quality hook активируется только когда external
  provider отсутствует» — детекция «отсутствует» и правила
  переключения не спроектированы.
- **J — UNRESOLVED (критичный блокер Step 6)**. На Debian 12 history
  settings — module arguments. Правильный ответ НЕ
  `/etc/pam.d/common-password` (generated file НЕ используется как
  FIC-owned option storage). Рабочая гипотеза: Debian 12:
  `PamOptionPolicy` мутирует ТОЛЬКО FIC-owned history slot
### Инварианты, зафиксированные fixture v2

- `--force` не является допустимым путём maintainer scripts FIC и не
  считается нормальным packaging flow. Production builder уже вызывает
  `--package` + `--enable` (postinst) и `--package --remove` (prerm)
  без `--force`. Упоминания `--force` допустимы только в
  negative/diagnostic экспериментах.
- rc=0 от pam-auth-update НЕ доказывает применение обновления и НЕ
  доказывает сохранность/перезапись локальных правок. Обязателен
  read-only proof resulting topology после любых вызовов.
- Validator не строится на «происхождении» файлов. Наблюдение «ручная
  запись `/var/lib/pam/*` без кэшированных строк отбрасывается
  pam-auth-update» остаётся diagnostic-фактом. Правильный invariant:
  selected profile state + generated physical include + managed slot
  state + journal provenance — exact resulting state независимо от
  способа создания файлов.
- Control-flow: `[success=end]` в профиле рендерится как
  `[success=N]` с динамическим N; ownership proof НЕ привязывается к
  абсолютным line numbers или конкретному jump count; «нормализация
  jump-count» в marker parser не нужна, если marker parser не
  анализирует эти строки. Разделять: (a) placement proof по generated
  common-password — anchored include rules без jump-значений;
  (b) managed-slot exact body proof — здесь допустим точный canonical
  body (наш файл).
- Режим pwhistory по платформам (сохранено из gate): Debian 12 —
  module-arguments; Debian 13/Ubuntu 24.04/26.04 — config-file mode
  (`/etc/security/pwhistory.conf`, дефолты `remember = 0`,
  `retry = 1`); `pam_pwhistory.so` входит в `libpam-modules` (пакета
  `libpam-pwhistory` не существует); дистро pwhistory-профиль
  отсутствует на всех четырёх платформах (`Conflicts: cracklib` у
  дистро pwquality на FIC hook не влияет).
- Дистро профили: `unix` (Priority 256, с `Password-Initial`),
  `pwquality` (1024, с `Password-Initial`), `mkhomedir`.
- Повторные `--enable`/`--disable` циклы пере-рендерят
## Accepted architecture / invariants

- **Faillock permanent-hook proof**
  (`fic_prove_permanent_hooks_attached`, генерируется
  `write_pam_hook_proof_function` в
  `packaging/deb/build-fic-debian12-deb.sh`, строго read-only):
  selection = exact full-line `Module: <profile>` в правильном
  facility state file; attachment = anchored full PAM include rule в
  generated common-*; prefix/suffix collision, wrong facility,
  комментарии, не-include control words не доказывают attachment;
  пруф никогда не вызывает PAM tools и не мутирует PAM state.
  Авторитетное описание: `docs/pam-owned-faillock-slots.md`.
- **prerm recovery восстанавливает ТОЛЬКО 4 faillock permanent hook**,
  никогда не legacy policy-owned selector profiles (включая
  `fic-pwquality`, `fic-pwhistory`).
- PasswordQuality/PasswordHistory managed topology строится по этой же
  модели (marker slots + mutation-id journal + placement proof) —
  контракт см. в Design checkpoint A–J выше; конкретные design решения
  фиксируются только после закрытия блокеров A/B/C/G/I/J.

## Completed

- Step 1 design gate correction (docs-only): fixture v2 без `--force`
  (см. «Fixture v2 результаты»), оригинальный checkpoint A–J со
  статусами RESOLVED/UNRESOLVED, точный placement/tie-break proof,
  инварианты §17/§18/§19. Production-код, тесты, packaging НЕ менялись;
  обновлён только `docs/HANDOFF.md`.

## Changed areas

- `docs/HANDOFF.md` (единственный изменённый файл; scratch-артефакты —
  `/tmp/pam-gate-v2/`, вне репозитория).

## Validation

- Docker fixture v2 (podman-backed docker CLI; НИГДЕ не использован
  `--force`): `r1-production`, `r2-initial`, `r34-negative`,
  `r5-behavior`, `r6-historyonly` — все на debian:12, debian:13,
  ubuntu:24.04, ubuntu:26.04 (PASS = наблюдаемое поведение получено и
  задокументировано). Авторитетное чтение `/usr/sbin/pam-auth-update`:
  tie-break sort, `--enable` ⇒ `--package`, local-modification branch,
  `get_template_md5sum`. Никаких изменений host-системы; контейнеры
  `--rm`.
- `git diff --check` — чисто; production-код/тесты/packaging не
  затронуты (изменён только `docs/HANDOFF.md`).

## Remaining

- **Step 1 закрыт НЕ полностью**: блокеры — A (topology), B (slot-набор),
  C (canonical neutral body), G (history-not-first design), I (quality
  ownership формулировка), J (Debian 12 option mutation source);
  D/E/F/H — design фиксируется в Step 2/3. Step 2 НЕ начинать, пока
  A/B/C/G не зафиксированы.
- Далее по плану: Step 2 (password slot topology + marker parsing в
  `fic/src/modules/identity_access/pam/`, модель
  `PamAuthUpdateTopologyManager`/faillock slots), Step 3 (journal-bound
  ownership), Step 4 (`PamSlotAttachValidator`), Step 5 (packaging:
  hook-профили + slot targets в `packaging/deb/`, extend permanent-hook
  proof на password hook), Step 6 (Debian 12 module-argument
  ownership), Step 7 (lift `PamPolicySupport::ReadOnly` →
  `RequiresTopologyActivation`; удалить
  `legacyPamAuthUpdatePasswordTopology` bypass последним), Step 8
  (обязательные тесты: PamCapabilityActivationPolicyTests,
  PamAuthUpdateTopologyManagerTests, PamSlotAttachValidatorTests,
  PamOptionPolicy/pwhistory argument tests, PlatformProfileTests,
  RollbackExecutorTests, PamPackagingChecks), Step 9 (docs).
- Infra: docker CLI = podman 5.8.5 (user socket
  `/run/user/<uid>/podman/podman.sock`; если `docker` отвечает «failed
  to connect to the docker API» — `systemctl --user start
  podman.socket` и/или экспортировать
  `DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock`). Daemon
  инжектит сломанный proxy env во все контейнеры — рабочая комбинация:
  `docker run --env http_proxy= --env https_proxy= --env HTTP_PROXY= --env
  HTTPS_PROXY= ...` (apt внутри работает).
