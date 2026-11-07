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
