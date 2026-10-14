# USER_CREATION — native Podman validation

Задача выполнена на базе `dc1b746dd40d30108b0ffb7d4a917610accd0cf4`
(`main`, завершённый SUDO C). Проверки выполнены 2026-10-14.
Контракт ownership: [rollback.md](rollback.md#user_creation-ownership-и-native-consumer).

## Production change

Изменены только:

* `fic/src/modules/identity_access/user_creation/UserCreationManagedTransaction.cpp`
* `fic/src/modules/identity_access/shared/login_defs/IdentityLoginDefsManagedTransaction.cpp`
* `fic/src/modules/identity_access/shared/login_defs/IdentityLoginDefsPolicySpec.h`
* `fic/src/resources/lang/ru.lang`
* `fic/src/resources/lang/en.lang`

Сохранены существующие typed journal payloads, persistent provenance,
Prepared/Applied recovery, single-write refresh, CAS/symlink/durability proof,
ownership-release и общий login.defs backend. Нового transaction backend,
policy ID, межполитической зависимости или snapshot rollback нет.

## Реальное окружение

Драйвер собирает production `UserCreationPolicies`, оба managed transaction
backend, `MutationJournal`, `fic-core`, `fic-policy` и выбранный platform profile.
Он отказывается работать вне root Podman-контейнера и проверяет настоящий
`/etc/os-release` через production `validateHostCompatibility`.
Никаких заглушек `useradd`/`adduser` нет. Версии получены внутри контейнеров
из `dpkg-query` / `rpm -q`, а не из имени образа.

| Платформа | shadow-utils (`passwd` для deb) | adduser | Проверки | Результат |
|---|---|---|---:|---|
| Debian12 | `1:4.13+dfsg1-1+deb12u2` | `3.134` | 118 | PASS |
| Debian13 | `1:4.17.4-2` | `3.152` | 120 | PASS |
| Ubuntu24.04 | `1:4.13+dfsg1-4ubuntu3.2` | `3.137ubuntu1` | 118 | PASS |
| Ubuntu26.04 | `1:4.17.4-2ubuntu3` | `3.153ubuntu1` | 120 | PASS |
| ALT p11 | `4.17.4-alt2.x86_64` | `/usr/sbin/adduser` штатного окружения, не supplementary provider | 100 | PASS; supplementary explicitly Unsupported |

Для ALT проверяются шесть поддерживаемых политик и отрицательный supplementary
apply без изменения системных файлов. `Unsupported` не засчитывается как
успешное применение этой политики. По supported gates нет FAIL/SKIP.

## Воспроизведение

Используются существующие native builders/runtime из SUDO-инфраструктуры.
Debian12 собирается в `localhost/fic-quarantine-test:debian12`, выполняется в
`localhost/fic-sudo-native-runtime:debian12`; ALT — builder
`localhost/fic-sudo-native:alt-p11`, runtime
`localhost/fic-sudo-native-runtime:alt-p11`. Остальные builders —
`localhost/fic-sudo-native:{debian13,ubuntu2404,ubuntu2604}`.

В некоторых фокусированных builders не было adduser. Штатный пакет установлен
только в новых container images посредством реально выполненного
`Containerfile.runtime`; production не менялся для обхода отсутствующего пакета.
Подготовка образов требует сети; сами native gates выполняются без сети:

```bash
bash tests/integration/user_creation/prepare-runtime-images.sh
bash tests/integration/user_creation/run-native.sh
# Можно выбрать одну или несколько строк:
bash tests/integration/user_creation/run-native.sh ubuntu2404 alt-p11
```

Каждая строка запускает две disposable `podman run --rm --network none` операции:
сборку и native gate. Монтируются только repository `/src:ro` и отдельный
`build-user-creation-native/<row>:/build:rw`. Host `/etc`, PAM, passwd/group,
home directories и security configuration не монтируются. Скрипт изменяет
реальные `/etc/default/useradd`, `/etc/login.defs`, `/etc/adduser.conf` и создаёт
реальные группы/accounts **только внутри контейнера**. ALT cached-image root
permission repair (`chmod 0755 /`) выполняется только в disposable runtime.

Для запуска с независимым log и ожиданием завершения использовалось:

```bash
nohup bash tests/integration/user_creation/run-native.sh \
  > /tmp/podman-fic-UC-final.log 2>&1 < /dev/null &
fic_uc_pid=$!
wait "$fic_uc_pid"
```

Основные команды каждой строки (точные image/target mappings — в run-native.sh):

```bash
podman run --rm --network none --entrypoint /bin/sh \
  -v "$repo:/src:ro" -v "$build:/build:rw" "$builder" \
  -c "cmake -S /src/tests/integration/user_creation -B /build \
      -DFIC_TARGET_PLATFORM=$target > /build/configure.log 2>&1 && \
      cmake --build /build -j2 > /build/build.log 2>&1"
podman run --rm --network none --entrypoint /bin/bash \
  -v "$repo:/src:ro" -v "$build:/build:rw" "$runtime" \
  /src/tests/integration/user_creation/native-gate.sh \
  /build/user_creation_native_driver "$row"
```

Логи: `build-user-creation-native/<row>/{configure,build,native-gate}.log`.
Итоговый runner: `/tmp/podman-fic-UC-final.log`. Подготовка images:
`<row>/runtime-image.log`, `/tmp/podman-fic-UC-runtime-prep.log`.

## Что доказано

* Каждая supported policy создаёт sub-block и Applied journal даже при
  fresh foreign compliance. Драйвер считает именно физические записи целевого
  native файла через transaction hooks: repeat=0, refresh=1. Запись intent в
  отдельный FIC config до вызова apply в этот счётчик не входит.
* Fresh/refresh release и repeated release проходят production coherence proof;
  foreign native файлы восстанавливаются **по текущим сохранённым байтам
  теста**, а не посредством snapshot rollback в backend. После release всех
  owners account/group databases остаются неизменными.
* Для каждой supported policy процесс действительно завершается `_exit(86)`
  после durable Prepared до и после физической записи. Следующий независимый
  процесс открывает persistent journal, восстанавливает Applied и освобождает
  ownership. Всего 68 process crashes: 7×2×4 + 6×2. Это реальные process cuts,
  не моделирование исключением и не эксперимент с физическим отключением питания.
* Все четыре `USERGROUPS_ENAB=no/yes × GROUP=users/staff` дают успешный apply
  обеих независимых политик. Native `useradd -D` получает целевой GROUP GID;
  реальный account получает configured group при no и одноимённую при yes.
* Реальные accounts подтверждают HOME, CREATE_HOME=yes/no, SKEL payload, SHELL,
  обновлённые defaults и `-g`, `-N`, `-U`, `-G`, `-m`, `-M`, `-d`, `-k`, `-s`.
  После overrides повторный apply остаётся успешным и zero-write.
* D12/U24 adduser добавляет audio/video с ADD_EXTRA_GROUPS=1. Empty владеет
  только ADD_EXTRA_GROUPS=0: foreign EXTRA_GROUPS остаётся byte-exact, новая
  учётная запись не получает этих memberships. Raw useradd ignores adduser.conf.
* D13/U26 useradd действительно добавляет audio/video с GROUPS и убирает их
  с GROUPS= после nonempty foreign assignment. Проверка отсутствующего foreign
  GROUPS тоже создаёт собственный empty override. `useradd -D` не используется
  как единственное доказательство membership: при empty оно может быть stale.
* D13/U26 native adduser наследует shadow GROUPS при выключенных собственных
  extras. Во всех четырёх deb-платформах frontend всё равно выбирает собственный
  `/home/<account>` и одноимённую primary group вместо FIC HOME/GROUP defaults:
  это явно проверено, а не объявлено ошибкой FIC.

## Unit/regression и общая validation

`UserCreationTests` сохраняет прежние foreign-compliant сценарии, меняя их
ожидание на собственный блок + no-write owned repeat. Параметризованная матрица
покрывает все семь политик и оба supported supplementary providers: fresh,
repeat, refresh, fresh/refreshed release, current foreign changes, peer owners,
manual drift, orphan, CAS race, Prepared before/after, external/repeated release,
final container cleanup. adduser.conf имеет только одну enrolled policy;
peer isolation там проверяется с настоящим владельцем другого native файла,
без выдуманной второй adduser-политики.

Общий IdentityLoginDefs набор проверяет совместные USER_CREATION/PASSWORD_AGING
owners, relation validation, provenance и crash recovery. PASSWORD_AGING foreign
compliance по-прежнему оставляет config без блока и journal. GROUP/private-group
metadata отдельно проверяется на отсутствие зависимостей.

Команды итоговой validation:

```bash
cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04
cmake --build build-check -j2
ctest --test-dir build-check -LE root --output-on-failure
bash -n tests/integration/user_creation/*.sh
git diff --check
```

Два root-only теста (`command_hash_batch_tests`,
`display_manager_transaction_tests`) пересобраны и выполнены в Debian12 Podman
с dropped DAC_OVERRIDE/DAC_READ_SEARCH: 2/2 PASS. Логи
`build-sudo-native/debian12/root-tests-UC-{build,ctest}.log`. Полная non-root
CTest validation:181/181 PASS, включая15 static checks; полная сборка PASS.
Логи /tmp/fic-UC-configure.log, /tmp/fic-UC-final-{build,ctest}.log.
Все183 CTest выполнены в соответствующих окружениях, без host root fullCTest.
Текущий snapshot: [HANDOFF](HANDOFF.md).

## Источники и границы доказательства

Перед изменением изучены история `a1c1319`, `3f0e4b7`, `eefc282` и актуальные
production/tests/docs. Native contract сверялся с
[shadow 4.13 useradd source](https://github.com/shadow-maint/shadow/blob/4.13/src/useradd.c),
[shadow 4.17.4 useradd source](https://github.com/shadow-maint/shadow/blob/4.17.4/src/useradd.c),
[Debian useradd manual](https://manpages.debian.org/trixie/passwd/useradd.8.en.html)
и [adduser.conf manual](https://manpages.debian.org/bookworm/adduser/adduser.conf.5.en.html).
Результат native vendor packages имеет приоритет над предположениями по upstream
версии; в частности display defaults GROUPS и actual membership различаются.

Не проверялись произвольные frontend, системные accounts с `-r`, LDAP/NSS
провайдеры вместо локальных групп, физические power-loss и release-wide package
rebuild/install. CMake language install и Debian/RPM staging проверены: оба
используют `cmake --install --component fic`, обновлённые ru/en.lang сохраняют
существующие пути. Host policy apply не выполнялся. CAS остаётся существующей
conditional atomic replacement, не kernel-atomic CAS против произвольного
некооперирующего writer. ALT supplementary implementation не добавлена.
