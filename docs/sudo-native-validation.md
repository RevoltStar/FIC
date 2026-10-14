# SUDO: текущая native проверка

Scoped/authentication integration и provider transitions проверены ниже.
Все описанные
эксперименты выполнялись в disposable Podman, без host `/etc`, PAM или
security mounts. Изменений host sudo provider нет.

## Реально выполненные scalar gates

| Платформа | Активный provider/version | Scalar native gate |
|---|---|---|
| Debian 12 | classic 1.9.13p3 | PASS |
| Debian 13 | classic 1.9.16p2 | PASS |
| Ubuntu 24.04 | classic 1.9.15p5 | PASS |
| Ubuntu 26.04 | classic 1.9.17p2 | PASS |
| Ubuntu 26.04 | sudo-rs 0.2.13-0ubuntu1.2 | PASS behavioral gate |
| ALT p11 | classic 1.9.17p2 | PASS |

Classic gate — `tests/integration/sudo/global-native-gate.sh`: реальные
production policy apply, повторное применение, смена значения, native
effective Defaults, игнорирование `.conf` в includedir и явное подключение
на EOF, contextual Defaults, отказ при foreign suffix, независимый rollback
и точное восстановление исходных байтов основного файла.

sudo-rs не показывает Defaults в `sudo -l`; использование classic assertion
первоначально остановило gate. Заменяющая native проверка —
`rust-behavior-native-gate.sh`: реальный PATH команды, удаление переменной
окружения, число запросов неверного пароля (3→4), разрешение без нового
пароля после успешной аутентификации при timeout10 и отказ при timeout0.
Также проверены `.conf`/EOF через PATH, repeated apply, foreign suffix
и независимый rollback. `env_reset`/`exempt_group` создают ноль records.

`provider-transition-native-gate.sh` PASS на Ubuntu26: classic ownership
env/exempt безопасно освобождается после перехода к sudo-rs; passwd_tries
остаётся owned. Последний release восстанавливает точные исходные байты.
Возврат к classic создаёт и освобождает настоящую env_reset ownership.
Alternatives переключаются исключительно внутри тестового контейнера.

Native drivers собраны отдельно в matching distro containers из настоящих
production исходников. Локальные полные logs находятся в ignored
`build-sudo-native/`: Debian12 `debian12/final-scalar.log`, остальные
`min-<platform>/final-scalar*.log`, Ubuntu26 дополнительно
`provider-transition-gate.log`; crash logs — `crash-gate*.log`.

## Существенные платформенные различия

* Classic использует mode0440; ALT native visudo требует0400. Cached ALT
  builder потребовал восстановления RPM permissions/owners, а disposable
  `/` —0755; точный package fragment `99-sudopw` нормализован0400 только
  внутри контейнера. Packaged ALT не разрешает root команды через sudo:
  global gate добавляет отдельное fixture rule. User authorization probes
  включают native `control sudo wheelonly` и добавляют fixture user в wheel.
* Для sudo-rs проверены unconditional env_reset и отказ native visudo от
  global/negated/contextual exempt_group. Это provider guarantee, а не
  записанный FIC-owned параметр или пропущенная проверка.
* В протестированной sudo-rs конфигурации более поздний global timeout10
  перекрывает ранее загруженный user timeout0; native timestamp cache
  проверен реальными командами. Classic сохраняет приоритет contextual
  значения в аналогичной проверке. Чужие contextual байты не удаляются.
* sudo-rs отвергает continuation внутри command arguments. Continuation
  после запятой command list принимает; реальные разрешённые/запрещённые
  команды подтвердили сохранение аргументов и inherited NOPASSWD. Этот
  результат не допускает произвольные multiline authentication rewrites.

## Оставшиеся проверки

Этап B: `scoped-native-gate.sh` PASS во всех шести строках матрицы —
по7 проверок на classic и8 на sudo-rs, всего43 проверяемых результата,
FAIL0/SKIP0. Среди них24 сочетания global/scoped apply/release, сохранение
command argument permissions, native PATH/environment, byte-exact foreign
source rollback, отказ от injected contextual Defaults внутри owned global
файла и wrappers с неподтверждённым policy name. На classic дополнительно
доказан Conflict при изменённом unterminated prefix и безопасный retry после
scoped release. sudo-rs отвергает no-final-LF rules/main до мутаций; negative
tests подтверждают сохранение исходных байтов, это не успешная поддержка
такой грамматики. Logs — `scoped-gate*.log` в тех же native build directories.

После B: полная build PASS, non-root CTest PASS179/179, два root-only tests
пересобраны/выполнены в Debian12 Podman PASS2/2. Scoped lifecycle suite
содержит81 реально выполненную test function, включая новые shared-resource
проверки; native harness вызывает production policy apply и production
transaction release, а не daemon IPC.

`crash-native-gate.sh` PASS по всем шести строкам матрицы: 15 process-crash
boundaries на строку, всего90. Принудительный `_exit` проверяет fresh/refresh
до Prepared, после Prepared, после file/include/postcondition, last release
после file/inert/detach/delete и independent release при surviving owner.
Каждый restart подтверждает native visudo, recovery и точный final main hash.

Полная project build PASS. Первый host sandbox CTest запуск: 11 failures,
4 skips из181 (socket/NSS ограничения и root-only fixtures). Повтор всех
failed fixture tests вне sandbox без root-only display-manager теста PASS;
три socket skipped tests PASS после повторного запуска. Два root-only tests
(`display_manager_transaction_tests`, `command_hash_batch_tests`) собраны
и выполнены в Debian12 Podman без DAC_OVERRIDE/DAC_READ_SEARCH: PASS2/2.
После последнего orphan-include hardening полный non-root CTest вне sandbox
PASS179/179; root-only Podman PASS2/2. Итого все181 test cases выполнены
успешно в подходящих окружениях; это два отдельных CTest запуска. Дополнительные global recovery и
malformed-journal regressions после полной сборки также PASS.

Authentication contract и финальная валидация C остаются.
Успех scalar gates не означает завершение всей задачи A/B/C.

## C: завершённая проверка (2026-10-14)

Typed authentication transformation, FIC_AUTH original/replacement frames,
independent proofs, multi-file journal/recovery/compensation и subset release
подключены к production apply и rollback dispatcher. Enrollment — Supported.
Old irreversible mutator удалён. Поддерживаемый grammar и fail-closed граница
описаны в rollback.md; никаких автоматических alternatives switches нет.

### Authentication native matrix

| Платформа | Активный provider/version | Auth gate | Provider transition |
|---|---|---|---|
| Debian12 | classic1.9.13p3 | PASS14 checks | — |
| Debian13 | classic1.9.16p2 | PASS14 checks | — |
| Ubuntu24.04 | classic1.9.15p5 | PASS14 checks | — |
| Ubuntu26.04 | sudo-rs0.2.13-0ubuntu1.2 | PASS16 checks | PASS rs→classic |
| Ubuntu26.04 | classic1.9.17p2 | PASS14 checks | PASS classic→rs |
| ALTp11 | classic1.9.17p2 | PASS14 checks | — |

86 auth outcomes +2 transition outcomes,0 FAIL,0 SKIP в итоговых gates.
Каждая строка проверяет настоящий sudo/visudo на native /etc/sudoers:
password-required после apply, разрешённые и запрещённые args, mixed/inherited
tags, repeat apply, drift refusal/retry, оба scoped/auth orders, requested
no-record guards по возможностям provider-а, nested include/aliases/Runas,
foreign concurrent comment preservation и byte-exact release. Classic также
проверяет CRLF original и native no-final-LF rollback.

Process cuts `_exit(86)` проходят before Prepared, after Prepared, after first
multi-file write, after postcondition и during partial release:30 C process
crash cases. Fresh/refresh normalization, journal failure и drift на отдельных
границах дополнительно проверяются unit fault injection. Это process crash,
а не физический power-loss experiment.

На sudo-rs native validator отвергает сам Defaults authenticate и CRLF
Defaults directive. Negative gates доказывают отказ до мутаций и сохранение
байтов; positive rs fixture использует native-valid LF и NOPASSWD. FIC не
нормализует неподдерживаемые входы. Контекстный timestamp_timeout используется
для проверки независимой scoped policy в обоих apply/release orders.
Classic поддерживает contextual!authenticate: независимое освобождение,
восстанавливающее нарушение surviving REQUESTED policy, возвращает Conflict.

### Матрица семи policy lifecycle

Все семь policies имеют explicit Supported enrollment; unknown future policies
не получают automatic enrollment. Global SUCCESS не означает подавление всех
контекстных overrides; этим владеет отдельная scoped policy.

| Policy | Classic apply/ownership | sudo-rs apply/ownership | Disable |
|---|---|---|---|
| sudo_env_reset=ENABLE | owned global Defaults | VerifiedByConstruction, no mutation | release own key / proven NothingToDo |
| sudo_passwd_tries | owned global Defaults | owned global Defaults | release only own key |
| sudo_securepath | owned global Defaults | owned global Defaults | release only own key |
| sudo_timeout | owned global Defaults | owned global Defaults | release only own key |
| sudo_exempt_group_disable=DISABLE | owned!exempt_group | VerifiedByConstruction, no mutation | release own key / proven NothingToDo |
| sudo_disable_scoped_defaults=ENABLE | FIC_SUDO_DISABLED frames | same frame model | exact release, guarded by surviving requested auth |
| sudo_require_authentication=ENABLE | FIC_AUTH for NOPASSWD /!authenticate | FIC_AUTH for supported NOPASSWD | exact release, guarded by surviving requested scope |

Compliant auth/scoped state creates no fictitious mutation. Global configurable
fields are owned even when foreign state happens to be compliant. Last global
owner removes only proven disconnected artifacts. Drift/unknown ownership is
Conflict; absent own frame can be NothingToDo only after ownership proof.

Five scalar→scoped dependencies changed Required→Recommended in A. The
provider-aware Required authentication→exempt dependency remains for classic,
is inapplicable by proven construction on rs, and stays fail closed for unknown
capabilities. C adds runtime ownership/requested-state coordination, not a
static dependency cycle. Requested scope may protect auth release even if its
failed apply created no record; no-record auth may protect scope release.

### Команды native запуска

После native compilation driver в каждом matching distro image выполнялся:

```sh
podman run --rm --network none --entrypoint /bin/sh \
  -v "$repo:/src:ro" -v "$repo/build-sudo-native/$row:/build:rw" "$image" \
  -c "$prelude sh /src/tests/integration/sudo/authentication-native-gate.sh $driver > /build/C-auth-gate-$flavor.log 2>&1"
```

repo = текущий FIC2.0 checkout. Row/runtime/driver:

| Row | OCI runtime | Driver |
|---|---|---|
| debian12 | localhost/fic-sudo-native-runtime:debian12 | /build/tests/sudo_native_driver |
| min-debian13 | localhost/fic-sudo-native:debian13 | /build/sudo_native_driver |
| min-ubuntu2404 | localhost/fic-sudo-native:ubuntu2404 | /build/sudo_native_driver |
| min-ubuntu2604 | localhost/fic-sudo-native:ubuntu2604 | /build/sudo_native_driver |
| min-alt-p11 | localhost/fic-sudo-native-runtime:alt-p11 | /build/sudo_native_driver |

Ubuntu26 classic prelude выбирает /usr/bin/sudo.ws, rs остаётся активным default
/usr/lib/cargo/bin/sudo. ALT prelude в disposable container исправляет exact
cached metadata: chmod0755 / и0400 /etc/sudoers.d/99-sudopw; native control
sudo wheelonly применяется самим gate. Host metadata не затрагивается.
Provider-transition gate заменяет имя script на
 authentication-provider-transition-native-gate.sh исключительно в Ubuntu26.
Команды regression gates используют тот же wrapper с именами script из таблицы
выше; их native builders/targets и логи сохранены в build-sudo-native.

### Регрессии предыдущих этапов

На последнем driver повторены все шесть rows: provider-native-probe (27 checks),
scoped-native-gate (43 checks), classic global-native-gate (40 checks), rs
rust-behavior-native-gate (9 checks), crash-native-gate (90 process cases).
Global provider transition также PASS2. Все25 запусков gate scripts имеют exit0;
итоговых FAIL/SKIP нет. Итого120 process crash cases A+C.

### Local validation и evidence

* Full configure/build ubuntu24 fixture profile PASS; /tmp/fic-C-complete-configure.log,
  /tmp/fic-C-head-build.log.
* Full non-root CTest181/181 PASS вне sandbox; /tmp/fic-C-head-ctest.log.
  Root-only command_hash_batch_tests и display_manager_transaction_tests
  пересобраны/запущены Debian12 Podman с DAC_OVERRIDE/DAC_READ_SEARCH dropped:
 2/2 PASS; build-sudo-native/debian12/root-tests-C-{build,ctest}.log.
  Это все183 tests в подходящих окружениях, не единый root fullCTest.
* Grammar20 checks и lifecycle17 cases PASS; production dispatcher regression
  включает requested scope без собственного record, RollbackFailed retry,
  exact restoration, NothingToDo и orphan refusal. Все dispatcher cases PASS:
  /tmp/fic-C-dispatcher-cases.log.
* Native build logs C-{configure,build}.log; auth logs C-auth-gate*.log и
  C-auth-transition.log в build-sudo-native/{debian12,min-debian13,min-ubuntu2404,
  min-ubuntu2604,min-alt-p11}. Regression logs C-regression-*.log там же.
* Запуски: Podman --rm --network none, /src read-only, только build/log /build
  writable. Authentication scripts находятся в tests/integration/sudo/;
  реальные sudo/PAM/user/alternatives операции исключительно внутри контейнеров.

Первоначальные auto-review timeouts разрешились на повторе. Фоновый запуск
удерживает управляющий shell через wait и пишет отдельный log; shell exit0
без wait не является доказательством завершения дочернего gate. Исходные
rs!authenticate/CRLF и non-ignored nested-directory fixtures были native-invalid;
negative cases сохранены, positive fixtures приведены к доказанному native
syntax. Production security contracts не ослаблены ради тестов.

Ограничения: неизвестный provider/version fail closed; неподдерживаемая
часть grammar не преобразуется. Shared-source writes используют существующую
conditional atomic-write модель, которая не является kernel-atomic CAS против
произвольного non-cooperating writer. Drift/ambiguity сохраняет provenance.
Runtime Containerfile recipes из A соответствуют использованной подготовке,
но отдельно заново как recipes не собирались; использованы существующие OCI
images. Host security configuration не изменялась; push не выполнялся.
