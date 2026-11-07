# PAM R1: capability, dependency и ownership contracts перед I3

Исходная точка: `8a1c24bc0c356a908230a6e2e406b04f20651a22`, main.
R1 не изменяет production-код. Research-driver вызывает production
`initPolicyRegistry` и существующий каталог, а не копирует регистрацию.
Файлы конфигурации для регистрации копируются в отдельный временный каталог;
policy apply при аудите registry не вызывается.

Обозначения: **STATIC** — исходники/история; **NATIVE-REGISTRY** — реально
скомпилированный selected profile и построенный registry; **NATIVE-CONTROL** —
отдельный disposable ALT experiment; **UNKNOWN** — не доказанный runtime effect.
Результаты фиксируются в `tests/integration/pam-dependencies/r1-evidence.json`.

## 1. Основание и история

Изучены main_function, PamOptionPolicy/PasswordHistoryOptionPolicy,
PamCapabilityActivationPolicy, PamProviderCatalog/PlatformComposition,
PamTopologyManagerFactory/CapabilityVerifier, topology managers,
PolicyExecutionPlanner/DependencyGraph, disable flow, RollbackExecutor/PamRollback,
provider executors/release, C2 coordinator и пять selected profiles.

Ключевые переходы истории (не замена проверки текущего кода):

* `1792350`, `22c6901` (август): ALT control integration и hardening;
  `ef483fa`, `9158bd2`, `cdede68` — capability/native passwdqc и транзакционные
  semantic contracts; `1fa5802` — trusted ALT service aliases и remember semantics.
* `ce1c9fe`, `55499fe`, `de86d56` — PAM rollback, два ALT faillock targets,
  стратегия preauth_required/preauth_requisite/authsucc.
* `82af579` (сентябрь): C2 joint password coordinator и evidence-based mutable
  lift; `17593cc` — C2 history module arguments; `f54530d` — последующий lift
  Debian13/Ubuntu26.04. В текущих четырёх Debian/Ubuntu profiles mutable=true.
* Step7B–7F (`7185b8d`, `ad6dd50`, `3a36687`, `28ce8cb`, `b61e616`,
  `5e03e74` и follow-ups): managed provider entries/flags и release.
* `76273c7` (октябрь): ALT passwdqc managed-provider rollback;
  `94d8904`, `da4c563` — maintenance admission/PAM release proofs.

Сравнение с первичными источниками:
[Linux-PAM control/include/substack](https://raw.githubusercontent.com/linux-pam/linux-pam/master/doc/man/pam.conf-syntax.xml)
различает участие модуля и управляющий эффект PAM return codes. Наличие строки
не доказывает обязательность её выполнения. FIC использует собственный ограниченный
control-flow verifier, а не считает произвольный PAM-граф автоматически поддержанным.
[pam-auth-update(8)](https://manpages.debian.org/bookworm/libpam-runtime/pam-auth-update.8.en.html)
описывает пакетные profiles, сохранение local changes и особый --force.
Поэтому выбранное имя profile не является причинным ownership proof.
ALT wiki Control/PAM при обращении возвращала Anubis, package site — cache miss;
их содержимое не использовано как доказательство. ALT primary evidence —
установленные RPM, native `/etc/control.d/facilities/system-auth` и конфиги
pam-config в disposable p11. Вторичные статьи не использованы для вывода контрактов.

## 2. Матрица текущих capability (STATIC; сверяется native registry)

`RTA` = RequiresTopologyActivation. Все строки AuthenticationLockout используют
pam_faillock, три объявленные стратегии и ProviderConfigFile.

| Profile | Quality | History | Lockout |
|---|---|---|---|
| Debian12 | pwquality / PamAuthUpdate / RTA / activation есть | pwhistory / C2 ModuleArguments / RTA / есть | PamAuthUpdate owned slots / RTA / есть |
| Debian13 | pwquality / PamAuthUpdate / RTA / есть | pwhistory / ProviderConfigFile / RTA / есть | PamAuthUpdate owned slots / RTA / есть |
| Ubuntu24.04 | pwquality / PamAuthUpdate / RTA / есть | pwhistory / ProviderConfigFile / RTA / есть | PamAuthUpdate owned slots / RTA / есть |
| Ubuntu26.04 | pwquality / PamAuthUpdate / RTA / есть | pwhistory / ProviderConfigFile / RTA / есть | PamAuthUpdate owned slots / RTA / есть |
| ALT p11 | passwdqc / StaticVerifyOnly / Supported для его bindings / activation **нет** | pwhistory / AltTcbManaged / RTA / есть | AltTcbManaged / RTA / есть |

Unsupported feature не регистрируется. В selected profiles нет зарегистрированного
ReadOnly feature; этот маршрут существует при отключённом password runtime lift
или отсутствии конкретного module-argument evidence. Тогда параметры по текущему
registerPamPolicy всё ещё регистрируются, а representative-based activation
registration может пропустить capability. Это тоже нужно закрыть в I3 без нового
writer. `ReadOnly` не следует трактовать как универсальную гарантию отсутствия
любых parameter writes: фактический маршрут определяется executor/configurationMode.

Устаревшие комментарии отдельных profiles и password-раздел
`pam-owned-faillock-slots.md` описывают прошлое ReadOnly состояние. Текущий код,
mutable flags и отдельные C2 contracts имеют приоритет; наличие флага само по себе
не считается повторным функциональным native-тестом C2.

## 3. Матрица параметров и зависимостей до/после I3

Четыре D/U = Debian12/13, Ubuntu24.04/26.04. `Rec` = Recommended activation;
`нет` = отсутствует dependency; `—` = Unsupported, policy не зарегистрирована.
Каноническое соответствие feature→capability берётся только из
`pamPolicyCapability`, имя activation — `pamCapabilityActivationPolicyName`.

| Canonical policy | Capability | Четыре D/U сейчас | ALT сейчас | I3 для зарегистрированных |
|---|---|---|---|---|
| password_min_length | Quality | Rec | — | Required enable_password_quality |
| password_min_classes | Quality | Rec | — | Required enable_password_quality |
| password_check_username | Quality | Rec | — | Required enable_password_quality |
| password_check_gecos | Quality | Rec | — | Required enable_password_quality |
| password_quality_enforce_for_root | Quality | Rec | нет | Required enable_password_quality |
| password_min_changed_characters | Quality | Rec | — | Required enable_password_quality |
| password_min_lowercase | Quality | Rec | — | Required enable_password_quality |
| password_min_uppercase | Quality | Rec | — | Required enable_password_quality |
| password_min_digits | Quality | Rec | — | Required enable_password_quality |
| password_min_other | Quality | Rec | — | Required enable_password_quality |
| passwdqc_strength_thresholds | Quality | — | нет | Required enable_password_quality |
| passwdqc_passphrase_words | Quality | — | нет | Required enable_password_quality |
| passwdqc_match_length | Quality | — | нет | Required enable_password_quality |
| passwdqc_similar_password | Quality | — | нет | Required enable_password_quality |
| passwdqc_retry_count | Quality | — | нет | Required enable_password_quality |
| password_history_depth | History | Rec | Rec | Required enable_password_history |
| password_history_enforce_for_root | History | Rec | Rec | Required enable_password_history |
| failed_authentication_attempts | Lockout | Rec | Rec | Required enable_authentication_lockout |
| failed_authentication_counting_period | Lockout | Rec | Rec | Required enable_authentication_lockout |
| failed_authentication_enforce_for_root | Lockout | Rec | Rec | Required enable_authentication_lockout |
| failed_authentication_unlock_time | Lockout | Rec | Rec | Required enable_authentication_lockout |

Lockout options дополнительно имеют Recommended disable_nopasswdlogin, когда
profile объявляет этот control. Её strength не меняется. Активационные Q/H/A
не должны получать искусственных зависимостей друг от друга. Production graph
validator уже отклоняет missing refs, duplicate/conflicting strengths и cycles.

## 4. Активация, Structural, чужая topology и rollback

Все activation freshness proofs используют Structural. Он проверяет provider
files/config contract, допустимую topology и обязательность provider в объявленном
scope через PamControlFlowAnalyzer. SecurityEffective отдельно проверяет защитные
значения. Поэтому enforcing=0/remember=0 не следует лечить новой activation-policy
в I3. Broken/conflicting/unsupported graph остаётся отказом.

| Domain | Actual apply/ownership | Release и ограничения |
|---|---|---|
| D/U password Q+H | C2 joint coordinator; permanent slots и общий desired state. Поддержанные foreign states сохраняются, ownership не присваивается просто по выбранному profile | C2 joint release, включая history-initial/consumer, без искусственной graph-связи H→Q. Не отдельные независимые writers |
| D/U faillock | PamAuthUpdateTopologyManager, permanent hooks + managed slots с journal mutation ID/strategy; Structural recheck. Только поддержанный foreign graph может быть observation | UndoDisablePamCapability, bind journal ID к физическим markers; partial/wrong-ID/orphan fail-closed. Снять можно только доказанные свои slots |
| ALT faillock | AltPamFaillockTopologyManager; два local-only targets, strict FIC blocks/сохранённый tcb anchor, три стратегии | Exact known blocks, optimistic CAS, проверка relevant graph; физические markers не journal MutationId. Произвольная foreign topology не принимается автоматически |
| ALT history | AltPamPasswordHistoryTopologyManager; strict block, pam_tcb, pwtxn/storage contract, topology/transaction locks | Удаляет свой block, сохраняет tcb и историю; не independent rollback каждого параметра. Unavailable/busy/conflicting state — отказ |
| ALT quality | StaticVerifyOnly manager: Structural proof, Enabled/manageable=false; canEnable/enable/disable отказывают | Activation apply уже реализован без journal/writer. Unrecorded static rollback возвращает AlreadyReleased, стек не меняет; mismatching active journal — конфликт |

В mutable topology policy код сопоставляет active journal и физическое ownership.
Applied без доказанной своей topology, orphan owned topology без journal,
несовпадающие identifiers/strategy и неразрешённый Prepared не становятся success.
Конкретная recoverability зависит от backend; одинаковых гарантий для ALT blocks,
C2 slots и faillock ID slots не заявляется.

## 5. Provider parameters — отдельный lifecycle

| Параметры / platform | Executor / placement | Persistent release |
|---|---|---|
| pwquality assignments, D/U | PamProviderManagedEntryExecutor / primary EOF | Journal-bound own entry, release-only, не восстановление истории |
| pwquality enforce_for_root, D/U | PamProviderManagedFlagExecutor / EOF | Own flag/sentinel + авторизованные suppression wrappers |
| faillock scalar/flag, все пять | ManagedEntry / ManagedFlag, EOF | Shared provider lock + journal/physical proof |
| pwhistory depth/root, D13/U24/U26 | ManagedEntry / ManagedFlag, beginning (native first-match) | Тот же provider release, включая отдельную creation authority контейнера |
| pwhistory depth/root, D12 | PamPasswordHistoryOptionPolicy → C2 module-arguments coordinator | Сам параметр NotEnrolled; rollback всей capability существует в C2 domain |
| pwhistory depth/root, ALT | Legacy option-file transaction в fic-pwhistory.conf + общий managed topology/storage lifecycle | Не отдельный provider entry journal; выключение параметра не приравнивается к rollback всей History capability |
| passwdqc пять параметров + root, ALT | ManagedEntry primary EOF; root — assignment с provider encoding | 76273c7 добавил shared provider ownership/release; не activation writer |

Transient PamConfigFileTransaction compensation при неудачном apply не равна
persistent rollback при disable. Managed-provider rollback работает по физическому
ownership и journal, не требует свежего Structural/activation proof для удаления
своего entry. Package release имеет собственный порядок: ALT topology domains,
provider domain, затем C2 password domain и per-policy обработка. Required graph
не должен превращать освобождение provider state в новый capability preflight.

## 6. Минимальный I3

1. PamOptionPolicy: для любого зарегистрируемого feature заменить Rec на ровно
   один Required через существующий capability mapping; сохранить Recommended
   disable_nopasswdlogin.
2. main_function: собирать capabilities реально зарегистрированных параметров и
   регистрировать по одной activation для каждой. Не проверять только
   representative PasswordMinLength: для ALT passwdqc он Unsupported, хотя
   root/пять passwdqc bindings Supported. Не создавать refs на отсутствующие policy.
3. Использовать уже существующий StaticVerifyOnly factory/Structural apply и
   unowned rollback; не добавлять writer. Аналогично закрыть ReadOnly registration
   без расширения mutable topology support.
4. Общий planner уже задаёт ownApplyAttempted=false и
   RequiredDependencyBlocked. Reverse enabledRequiredDependents проверяется
   production disable перед rollback. Дублировать checks в backend не нужно.
5. Сначала тестами подтвердить отсутствие необходимости менять RollbackExecutor,
   C2 и package lifecycle. Перестройка этих механизмов не является I3.

## 7. Проверки R1

* STATIC: просмотрены перечисленные исходники, docs/rollback PAM sections,
  существующие structural/activation/provider/wiring tests и история августа–октября.
* NATIVE-REGISTRY: research-driver строится на production source closure без
  daemon main и вызывает реальный initPolicyRegistry. Сводка результатов и hashes
  фиксируются в r1-evidence.json; это не функциональный PAM login/password test.
* NATIVE-CONTROL: отдельный ALT probe с native control и настоящим manager,
  временно суженным authentication scope. Не заявляет успех stock global scope.
* Host PAM не изменяется. Docker используется как ранее согласованный disposable
  runtime; сеть отсутствует, source mount read-only только в build/audit containers.

### Фактический результат R1

NATIVE-REGISTRY: все пять сборок и production registry/graph checks PASS.
Debian12/13, Ubuntu24.04/26.04: по16 зарегистрированных параметров; ALT:12.
На ALT ровно6 Supported quality options без activation и без dependency.
На четырёх D/U каждый зарегистрированный параметр имеет Recommended activation;
на ALT history/lockout тоже Recommended. Ни один результат не является доказательством
PAM authentication или фактического выполнения password-changing consumer.

NATIVE-CONTROL: pam-config1.10.0-alt0.p11.2, control0.8.0-alt3,
pam0_passwdqc2.0.3-alt3, pam1.7.1-alt1. Настоящий faillock manager успешно
создал blocks в двух native local-only files при scope={system-auth}.
Переключения multi → ldap → local завершились exit0: local-only bytes сохранились,
manager.inspect оставался Enabled/manageable. Следовательно, утверждение
«control всегда удаляет физические blocks» для этих условий неверно. Штатный
facility меняет symlinks, а не содержимое этих файлов. Это не доказывает поддержку
всех modes, внешних providers, stock global services или package upgrade.
Первоначальный fixture с system-auth-use_first_pass как самостоятельным root
не прошёл account-call proof и был компенсирован manager; этот auxiliary stack
не следует ошибочно считать полным authentication service.

## 8. Вне scope I3

* ALT block MutationId и устранение неоднозначности legacy physical ownership.
* Изменение ALT managers при control switching, новые aliases/foreign adoption.
* Переоценка всего passwdqc/quality enforcement, новые enforcement policies.
* C2 ownership/redesign, новые runtime-recovery и миграции.
* Изменение package release order или общего rollback engine.
* Исправление stale documentation/comments за пределами этого research report.
* Полная функциональная auth/password-change матрица и произвольные сторонние
  PAM-графы. Existing tests/interfaces не заменяют такое доказательство.

## 9. I3: обязательное участие capability

R1-матрица выше и `r1-evidence.json` остаются историческим снимком до I3.
После I3 каждый зарегистрированный `PamOptionPolicy` имеет ровно одну
безусловную Required-зависимость на activation своей canonical capability:

| Параметры | Required activation |
|---|---|
| 15 quality identities из §3 (зарегистрированные bindings выбранного provider) | enable_password_quality |
| password_history_depth, password_history_enforce_for_root | enable_password_history |
| failed_authentication_attempts, failed_authentication_counting_period, failed_authentication_enforce_for_root, failed_authentication_unlock_time | enable_authentication_lockout |

Это относится к Supported, ReadOnly и RequiresTopologyActivation. Регистрация
собирает capabilities **фактически зарегистрированных параметров**, а не
проверяет representative feature. Тем самым ALT получает verify-only
`enable_password_quality`, хотя PasswordMinLength для passwdqc Unsupported.
Сам факт регистрации ничего не активирует и не изменяет PAM.

Используются существующие `pamPolicyCapability`, activation name helper,
`PamCapabilityActivationPolicy`, factory/verifier и planner. Disabled/Failed
activation блокирует собственный apply параметра с
`RequiredDependencyBlocked`/`ownApplyAttempted=false`. Успешный Structural proof
сторонней поддержанной topology удовлетворяет Required без присвоения ownership.
StaticVerifyOnly не получает writer и не создаёт topology journal records.
Structural не доказывает enforcing password strength.

Reverse Required guard запрещает disable activation при ENABLE-параметрах.
Сначала освобождаются/отключаются параметры, затем activation. Provider rollback
сохраняет самостоятельный physical ownership proof: отсутствие/повреждение
activation не запрещает освобождение доказанных собственных entries.
Ни C2 joint Q/H, ни ALT-managed blocks, ни package release order не изменены.
Recommended disable_nopasswdlogin сохраняется **там, где профиль объявляет
passwordlessLoginControl**; activation-политики не получают взаимных зависимостей.

### Проверки I3

`tests/integration/pam-dependencies/run-i3.sh TAG PLATFORM BUILD_DIR` запускает
сборку `fic` и десяти test targets в выбранном native Docker builder, затем
12 CTest (включая два static checks). Для ALT предварительно собирается
`fic-pam-dependencies-native:alt-p11` из `Dockerfile.alt`: пакет `ctest` в ALT
отделён от `cmake`. Standalone Dockerfile восстанавливает build prerequisites без локального base image.
CTest добавляется только в disposable test image; зависимости
пакетов FIC не меняются. Остальные профили используют `fic-package-native:TAG`.
Runtime permission-negative fixtures
запускаются без DAC_OVERRIDE/DAC_READ_SEARCH. Рабочие PAM/resources — только
временные fixtures; host PAM не изменяется.

Новый `pam_dependency_contract_tests` строит **реальный production registry**,
проверяет все зарегистрированные параметры, будущие ReadOnly routes, missing
activation, executor suppression, reverse production disable и реальный
StaticVerifyOnly factory/verifier на изолированном passwdqc fixture.
Для всех5 выбранных профилей регистрация проверяется непосредственно; static
fixture отдельно моделирует supported foreign topology и не выдаётся за
функциональную аутентификацию на пяти ОС. Собственные parameter executors в
planner-сценариях подменены; Structural activation выполняется настоящая.

`PamProviderRollbackTests` дополнительно проверяет release при отсутствии
activation registry и отсутствующем/повреждённом effective stack. Existing
C2 wiring tests покрывают D12 history module args; provider rollback suite —
все6 passwdqc assignments, повторный apply/rollback и foreign bytes.
Фактические результаты и хеши приведены в `i3-evidence.json` рядом с harness.
Полная функциональная auth/password-change/package-manager E2E матрица этим
прогоном не заявляется; ограничения §8 сохраняются.

### Итог native validation I3

| Платформа | Фактически выполнено |
|---|---|
| Debian 12 | fic +10 test targets; 12/12 CTest PASS до очистки; Driver дополнительно PASS uid65534 |
| Debian 13 | fic +10 test targets; 12/12 CTest PASS до очистки |
| Ubuntu 24.04 | fic +10 test targets; 12/12 CTest PASS и registry audit завершены до очистки; Docker wrapper затем exit125 из-за containerd meta.db I/O |
| Ubuntu 26.04 | fic +10 test targets; 12/12 CTest PASS до очистки |
| ALT p11 | fic ранее собран; после восстановления Docker заново собраны10 test targets, 9/10 CTest PASS; исправлен существующий wiring supportContract, повторён только упавший suite: 1/1 PASS; registry audit PASS |

По просьбе пользователя после disk exhaustion/trim успешные проверки не
повторялись. Их исходные логи, build receipts и Docker images удалены при очистке;
результаты четырёх D/U сохранены по непосредственно наблюдавшимся tool outputs,
без выдуманного восстановления хешей. `i3-evidence.json` явно отделяет эти
результаты от новых ALT receipts/contracts/audit. Два generic static checks,
успешные до очистки, повторно не запускались. `git diff --check` выполнен в конце.

Первый ALT прогон выявил ошибку существующего testSupportContract: lift-флаг
PamAuthUpdate ошибочно распространялся на StaticVerifyOnly/AltTcbManaged.
Исправлены только тестовые ожидания: собственные topology-контракты ALT,
неизменность их support при переключении lift-флага, универсально поддержанный
PasswordQualityEnforceForRoot в static fixture вместо unsupported на passwdqc
PasswordMinLength. Production support/backend не изменён. На D/U прежние
lift-assertions сохранены; новая версия этого теста проверена только на ALT,
успешные D/U suites по указанию пользователя не повторялись.

Подтверждено16 зарегистрированных параметров на каждом D/U (Q10/H2/A4) и12
на ALT (Q6/H2/A4). Свежий ALT contract содержит36 planner cases. Native
libpasswdqc-devel parser probe не запускался; шесть passwdqc assignments
покрыты provider lifecycle regression suite, а не functional password change.

## 10. I1: Structural activation contract

База I1: `8ae2ebb84a10084044652594b7fe166e37df0324`. Разделы R1 и
`r1-evidence.json` — исторические; их выводы не переписываются задним числом.

### Что существовало и что исправлено

До I1 обычный single-manager apply уже выполнял inspect → preflight →
journal prepare → activation → physical ownership check → fresh Structural
proof → durability/Applied. Идемпотентный apply и foreign no-op тоже проходили
свежую проверку, а активные mutable journal records, orphan markers и
неподдерживаемые стратегии блокировали обход ownership. ALT managers уже
ограничивали собственные topology; StaticVerifyOnly уже не имел writer.
C2 уже был единственным joint Q/H writer с точными слотами, planner,
пооперационными ownership/durability proofs и своими recovery/compensation.
Эти механизмы сохранены.

Воспроизведены и исправлены локальные нарушения обычного apply:

* D/U permanent-slot faillock: при нейтральных FIC slots внешний граф
  обнаруживался, но `activeStrategy` не заполнялась. Настоящий Structural
  verifier принимал граф, а policy отказывала из-за неизвестной стратегии.
  Manager теперь использует существующий `detectUniformStrategy`; наличие
  provider само по себе не доказывает Structural. Policy независимо проверяет
  весь граф, requested strategy и отсутствие conflicting ownership.
* C2: selections/slot/order postconditions не заменяли проверки provider trust
  и PAM control-flow. Policy могла сообщить успех при отсутствующем модуле;
  quality apply мог создать history поверх стороннего pwhistory. В policy
  добавлены реальные Structural gates обоих членов Q/H до и после прежнего
  coordinator. Отсутствие проверяется по каждому существующему service:
  `Inactive` первого service не означает отсутствия во всём scope. Проверки
  не заменяют ownership/recovery и не возвращают success в обход coordinator.
  Дополнительный RED показал, что отсутствующий provider запрошенного peer
  нельзя считать optional: иначе slots публиковались до отказа AFTER proof.
  Узкий optional preflight callback существующего ordinary coordinator apply
  получает тот же immutable Q/H/options snapshot, который потребляет transition.
  Для всех запрошенных members требуется установленный trusted provider ДО
  записи; отсутствие незапрошенного peer допускается. Второго reader/config
  snapshot и самостоятельного writer не добавлено. Проверены отказ без slots/
  journal records для Missing requested peer и успешный Quality-only без него.
* Полный Structural proof выявил несовместимость legacy module-argument
  parser с уже поддержанным C2 history-initial. Этот producer получает токен
  сам, без `use_authtok`. Только Structural для C2 ModuleArguments допускает
  producer semantics initial-source. Полный C2 grammar/journal proof остаётся
  у coordinator. Само имя файла не доказывает ownership. Default evaluator,
  parameter preflight, option mutation и SecurityEffective сохраняют прежнее
  требование `use_authtok`; произвольный foreign initial history не принимается
  activation policy.
* C2 foreign no-op мог скрыть dangling active record: ownership snapshot
  сопоставлял records с существующими slots, но отсутствие slot не запрещало
  принять foreign quality. RED воспроизвёл SUCCESS при dangling Applied.
  Ordinary coordinator apply теперь после прежней transition/recovery вызывает
  read-only `confirmApplyOwnership` существующего executor: каждый active Q/H
  record обязан быть Applied и точно связан с выбранным owned slot. Prepared,
  Applied и RollbackFailed без такой связи возвращают failure без изменения
  records/files; проверены оба members. Policy не дублирует C2 ownership
  grammar/пути: проверка находится у executor с его прежним inspector.
  Явный `transition()` для rollback/release этот gate не вызывает. Это локальный
  I1 postcondition, а не новый recovery или journal transition.
* StaticVerifyOnly мог игнорировать активную запись от прежней mutable
  topology. Теперь наличие активного provenance для этой policy блокирует
  static apply. Запись не усыновляется, не удаляется и не мигрируется.

### Поддерживаемые платформенные маршруты

| Платформа / capability | Отсутствие | Foreign Structural-compliant | Собственная activation / reapply |
|---|---|---|---|
| Debian12/13, Ubuntu24.04/26.04 / Quality | Trusted provider без подключения во всех существующих services → C2 planner | Stock pwquality selection + соответствующий direct producer, совместимость с C2 и полный Structural → no mutation/no ownership | Прежний C2 quality slot; exact journal/physical proof, post-Structural; повторный apply no-op |
| Те же / History | C2 history-initial либо consumer согласно joint Q/H | Произвольный foreign pwhistory не представлен в C2 model → отказ до записи, без дублирования | Прежние парные slots/варианты, storage/options contracts; C2 proof плюс Structural; повторный apply сохраняет ownership |
| Те же / Lockout | Neutral permanent slots, нет external graph → прежний writer/strategy preflight | Uniform supported strategy + совпадение requested strategy + Structural при neutral FIC slots → success без ownership | Journal-ID-bound slots, прежние prepare/proof/durability transitions; повторный apply no-op |
| ALT p11 / Quality | Отказ; passwdqc writer отсутствует | Поддержанный passwdqc Structural, trusted configuration/modules, нет active policy provenance → success без файловой mutation и ownership | Собственная topology не создаётся |
| ALT p11 / History | Только прежний AltPamPasswordHistoryTopologyManager, tcb/pwtxn/storage preflight | Backend отказывает в произвольной внешней topology, даже когда отдельный общий verifier способен доказать Structural | Прежний строгий block: pwtxn begin → pwhistory → tcb → pwtxn end; transaction locks/storage, Structural; идемпотентность |
| ALT p11 / Lockout | Только прежний AltPamFaillockTopologyManager со строгими tcb anchors/targets | Backend не принимает произвольный внешний faillock как supported managed topology; отказ без дублирования | Прежние FIC blocks, стратегии, CAS/durability и независимый Structural proof; идемпотентность |

Disabled означает доказанный BEFORE в поддерживаемой модели manager, а не
просто отсутствие строки или записи journal. Enabled описывает topology;
`manageable` и physical witness отдельно отличают FIC ownership от foreign.
Broken — malformed/conflicting/недоказанный graph или ownership; Unavailable —
недоступная инфраструктура, объект либо lock. Оба состояния завершаются отказом.
C2 использует собственные classification/coherence/safety/ownership gates,
а не искусственно подменяет их этими четырьмя состояниями manager.

Structural подтверждает provider/configuration trust в пределах существующих
проверок, участие во всех существующих services объявленного scope и отсутствие
допустимого успешного обхода механизма, включая поддержанные include/substack,
bracket controls и faillock strategy. Неизвестная семантика — fail-closed.
`enforcing=0`, `enforce=none`, `remember=0` сами по себе не превращаются в
Structural failure; это не доказательство защитного эффекта или native
прохождения конкретного password-change/authentication path.

Первичные источники сверены повторно:
[Linux-PAM control/include/substack](https://raw.githubusercontent.com/linux-pam/linux-pam/master/doc/man/pam.conf-syntax.xml),
[pam-auth-update(8)](https://manpages.debian.org/bookworm/libpam-runtime/pam-auth-update.8.en.html),
[Linux-PAM 1.5.2 pwhistory consumer](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.5.2/modules/pam_pwhistory/pam_pwhistory.c).
Последний вызывает pam_get_authtok и поддерживает собственное получение токена;
`use_authtok` относится к режиму использования уже полученного токена.
ALT Control wiki снова вернула Anubis, поэтому её недоступное содержимое не
считается проверенным; native ALT findings R1 и текущий код managers имеют
явно указанные границы поддержки.

### Вопросы I2 и границы доказательства

Prepared/Applied/RollbackFailed, partial slots, wrong IDs, orphan markers,
recovery, C2 compensation и rollback/package release в I1 не перепроектируются.
Fresh Structural failure не даёт права удалить доказанный physical ownership.
В частности, если C2 уже завершил свои пооперационные journal transitions,
а независимый AFTER proof обнаружил drift/обход, policy возвращает failure и
сохраняет активные записи. Их проверка/reconciliation — существующий lifecycle
и последующий I2, без автоматического восстановления/усыновления в I1.

ALT block MutationId/legacy ownership ambiguity, более широкие control modes,
произвольные foreign history/faillock и recovery redesign остаются отдельными
задачами. Проверка Structural не расширяет эту платформенную поддержку.

### Проверки I1

`run-i1.sh TAG PLATFORM BUILD_DIR` использует существующие disposable builders,
собирает fic и20 relevant targets и запускает22 targeted CTest (включая два
static checks). Source/build mounts изолированы, runtime без DAC_OVERRIDE и
DAC_READ_SEARCH, host PAM не меняется. Source receipts до/после gate должны
совпадать; audit реального selected-profile registry сохраняет контракт I3.
Unit/fixture tests скомпилированы нативными toolchains каждого дистрибутива,
но fake pam-auth-update runner и fixture `.so` не объявляются native
аутентификацией. Реальные managers/verifier/control-flow не подменяются там,
где утверждается Structural proof.

Дополнительно `native-initial-probe.sh` использует существующий fic_pam_probe.c
в отдельных disposable Debian12/13 и Ubuntu24.04/26.04: настоящий
pam_chauthtok для одноразового пользователя, pwhistory initial producer,
две успешные смены и отказ reuse.
Это узкий consumer probe, а не FIC activation E2E или функциональная матрица I6.
Фактические receipts и ограничения сохранены в `i1-evidence.json`:

| Native userspace/toolchain | fic +20 targets | Уникальные targeted CTest | Финальные affected suites | Native history-initial consumer |
|---|---|---|---|---|
| Debian 12 | PASS | 22 PASS | 8/8 PASS | PASS |
| Debian 13 | PASS | 22 PASS | 8/8 PASS | PASS |
| Ubuntu 24.04 | PASS | 22 PASS | 8/8 PASS | PASS |
| Ubuntu 26.04 | PASS | 22 PASS | 8/8 PASS | PASS |
| ALT p11 | PASS | 22 PASS | 8/8 PASS | Не запускался |

В ходе первых сборок уточнялись wiring/static fixtures и C2 postconditions.
Source-stability guard честно отклонял изменившийся во время итерации source
snapshot; эти wrapper failures не называются полным gate PASS. Финальные
incremental builds пересобрали затронутые leaf objects, после чего повторены
только восемь связанных suites. Остальные успешные suites не повторялись.
Все пять финальных before/after receipts совпали между собой и с текущими
кодом/тестами. Исправлен ложный static-check запрет слова control в комментарии;
прямой platform command literal/ExecutableId по-прежнему запрещён в policy.
Тестовая повторная инициализация runtime paths устранена выбором history mode
скомпилированного profile. Для stale object, созданного во время редактирования
translation unit, выполнена явная пересборка; он не используется как evidence.

Debian12 registry/Structural fixture также PASS uid65534 с read-only rootfs,
source/build mounts и отдельным tmpfs. В native consumer probes начальная
подготовка пользователя могла печатать warning об отсутствующем cracklib
словаре; сам probe использует явный pwhistory/unix stack и не доказывает
pwquality enforcement. Полная I6 authentication/password-change matrix,
native ALT consumers и FIC package/activation E2E не заявляются.

## 11. I2 — ownership admission перед новой C2 mutation

База: `04906dfd8683ddb3f2561a37282c329316aabb80`. Исторические R1/I1
результаты выше сохранены; I2 evidence публикуется отдельно в
`tests/integration/pam-dependencies/i2-evidence.json`.

**Воспроизведено (RED, production-код базы):** dangling Applied Quality при
foreign quality и запросе History сначала вызывал native mutator и создавал
peer ownership, затем отказывал на postcondition. Симметричный dangling
History при запросе Quality также допускал новую mutation до отказа.
Ранний coordinator preflight оставлял exact selected Active Prepared history
незавершённым при отказе по новому goal. Изменение topology внутри preflight
могло попасть в новый план без проверки against entry snapshot.

**Изменение:** один существующий executor обслуживает ordinary `apply()` и
explicit `transition()`. Ordinary порядок: fresh typed inspection → только
существующее exact Prepared history completion → usable-state proof →
существующий read-only `confirmApplyOwnership()` обоих доменов → Structural
preflight с тем же requested snapshot → существующий drift gate → прежний
planner/slot writers/native calls → прежний ownership/Structural AFTER proof.
Explicit transition/release не получает ordinary admission или activation
preflight. Grammar ownership, planner, MutationJournal schema и recovery
classifier не дублируются и не изменены.

### Journal / physical matrix

| Состояние | Ordinary apply | Explicit release |
|---|---|---|
| Нет active records, поддерживаемый foreign effective, нет собственных artifacts | No-op без adoption | NothingToDo, foreign сохранён |
| Нет journal, собственный active marker/selection | Отказ | Отказ, не удалять без provenance |
| Applied + exact selected owned slot/block | Прежний apply/idempotency | Прежний ownership-safe release |
| Applied + все собственные artifacts доказанно отсутствуют | Отказ, foreign не скрывает dangling provenance | AlreadyReleased без реконструкции artifact, если отсутствие доказано |
| Partial / wrong ID / malformed / неоднозначный ownership | Отказ перед новой ordinary mutation | Только предусмотренный exact release; иначе отказ |
| C2 HistoryNormal/HistoryInitial selected Active Prepared + neutral sibling | Прежнее exact completion с historical receipt, затем новый intent | Прежний explicit lifecycle |
| C2 Quality Prepared / неподдерживаемый Prepared / RollbackFailed | Отказ, нет расширения recovery | Только существующий доказанный release/package-release |
| Faillock Prepared exact BEFORE/AFTER или bound crash-partial | Прежний recovery; reused provenance не discard при Disabled | Exact ID-bound release; wrong/malformed ID отказ |
| ALT missing/corrupt/partial/unsupported block или foreign drift | Строгий supported-topology contract | Прежние строгие manager/lock/CAS proofs |

Это backend-specific контракт, а не единый новый recovery algorithm.
C2 absent-ownership rollback проверяется через настоящий RollbackExecutor/joint
transition, учитывает intent survivor и не удаляет foreign quality. Provider
entry rollback при отсутствующей/неэффективной activation уже покрыт
`testReleaseWithoutEffectiveActivation`; новых activation gates туда нет.

### Проверки и границы доказательства

Новые wiring regressions: оба направления peer mutation при
Prepared/Applied/RollbackFailed; byte-exact неизменность всех slots, generated
stack, selection и journal; explicit release Applied с доказанным отсутствием;
Normal/Initial exact completion перед отвергнутым изменённым intent (значения
7 и 11 не смешиваются), rebuild coordinator, неизменность slots/native count;
drift во время preflight. На базе четыре RED test groups, после исправления
GREEN. Existing F1–F12 executor fault tests продолжают проверять drift,
компенсацию, unproven compensation и сохранение provenance.

Real faillock manager + Structural verifier: neutral slots с foreign effective
не скрывают Prepared/Applied/RollbackFailed; журнал и graph неизменны при
отказе. Existing tests сохраняют exact partial release, wrong ID refusal,
orphan rejection и fresh/reused Prepared recovery. Real ALT history manager +
journal (verifier seam, не native efficacy proof): Applied idempotency,
missing block, corrupted/partial block, unsupported duplicate tcb и orphan
block fail-closed; supported foreign account rule сохраняется без изменения
provenance. Existing ALT managers покрывают tcb/pwtxn storage,
transaction contention, malformed markers, foreign topology и CAS replacement.
ALT faillock active provenance + foreign graph уже проверяется I1 regression.

Никаких новых causal ownership guarantees для ALT marker без MutationId:
известная неоднозначность исторического происхождения exact block остаётся
отдельной задачей. Автоматической миграции/adoption нет. Quality Prepared
recovery не расширен. ModuleArguments option policies, I3 Required edges,
package lifecycle и другие модули не меняются.

Native build/CTest и четыре disposable pwhistory consumer probes — bounded
validation. Они не являются полной PAM authentication/FIC activation I6
матрицей, native ALT passwdqc/history consumer proof или package E2E.

Итог I2 (2026-11-07): `fic` +20 relevant targets собраны на D12/D13/U24/U26/
ALT p11; на каждой платформе 22/22 relevant CTest и production registry audit
PASS. Финальные before/after receipts всех пяти совпадают; наличие новых
regression literals в итоговых executable дополнительно проверено против
stale objects. Четыре disposable native-initial-probe.sh — PASS. Условия
запуска: `FIC_PAM_GATE_STAGE=i2 bash tests/integration/pam-dependencies/run-i1.sh
TAG PLATFORM BUILD_DIR`. Источник точных хешей/версий и ограничений — отдельный
`i2-evidence.json`; промежуточные source-drift и ошибочное ожидание ALT fixture
не выдаются за финальный PASS.
