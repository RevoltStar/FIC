# Native OpenSSH end-to-end validation: Debian 12/13

Дата: **2026-10-19**. Base: `d3bcba86614173d6b7143326df407794cdca8699`.
Это интеграционное исследование, не реализация SSH adapter.

**Результат:** публичный `VerifiedConfigServiceActivator::activate()` действительно
перезапускает штатный Debian sshd, подтверждает новый процесс/READY и очищает
монтирования. Это проверено на Debian 12 и 13. Generic Success **не является**
сертификатом SSH policy compliance: испытаны реальные контрпримеры с внешним
Include, новым glob match и CLI overrides. Также найден отдельный metadata
compatibility blocker OverlayFS; production-код не исправлялся.

## 1. Среды, версии и воспроизводимость

| Userspace | OpenSSH package | systemd | Реальный FragmentPath |
|---|---|---|---|
| Debian 12 | `1:9.2p1-2+deb12u10` | `252.39-1~deb12u2` | `/lib/systemd/system/ssh.service` |
| Debian 13 | `1:10.0p1-7+deb13u4` | `257.13-1~deb13u1` | `/usr/lib/systemd/system/ssh.service` |

`sshd -V`: Debian12 — `OpenSSH_9.2` (network identification содержит 9.2p1);
Debian13 — `OpenSSH_10.0p2 Debian-7+deb13u4`. Версия source package Debian13
10.0p1 не должна подменять фактическую версию patched executable.

Обе среды — **disposable Docker с настоящим systemd PID1**, не ВМ. Общее ядро:
`6.6.87.2-microsoft-standard-WSL2`. `/dev/kvm` отсутствует; отдельные Debian VM/
дистрибутивные ядра **NOT_TESTED**. Не экстраполируем контейнерные результаты на
обычный boot физической машины.

[Machine-readable evidence](verified-config-openssh-native-evidence.json)
содержит immutable image IDs, версии, реальные unit properties, результаты
29 сценариев каждой Debian-среды и exact source hashes/patch series.
[Harness README](../tests/integration/verified_config_service/openssh_native/README.md)
содержит команды сборки/запуска и ограничения воспроизведения. Рецепт Containerfile
добавлен, но заново не собирался: использованы подготовленные
`fic-ssh-audit:debian12` и `:debian13`. Ротация apt repositories может потребовать
архив/snapshot с указанными версиями.

## 2. Независимый доступ и границы безопасности

Runtime runner: `--privileged --cgroupns=private --network none`, без published
ports, host binds/volumes, host PID/network namespace и Docker socket. Сборка
в отдельном непривилегированном контейнере с source read-only. Управление —
`docker exec`, не SSH. Runtime namespace/root должны отличаться от caller;
PID1 — systemd, network interfaces — только `lo`. Python и C++ требуют явный
runner token/marker. Root/CAP_SYS_ADMIN сами по себе не разрешают тесты.

Оригинальные config/Include directory/одноимённый host key сохранены **внутри**
disposable work directory; в конце восстановлены, `sshd -t` PASS. Генерируется
новый одноразовый ed25519 host key; реальные пользовательские credentials,
authorized_keys и PAM login не используются. Аутентификация fixture отключена.
Выгружается только sanitized results directory, не backups/keys/request files.

Штатные units не записываются. Для contract races меняется только тестовая
переменная **Manager.Environment** и затем удаляется. FragmentPath hash до/после
совпадает; DropInPaths пуст. Host SSH не вызывается; checks до/после показывают,
что перечисленные host SSH config/unit paths оставались отсутствующими.

## 3. Реальная launch/readiness модель

На обеих Debian-средах:

* canonical `Id=ssh.service`, `Type=notify`, `NotifyAccess=main`;
* `EnvironmentFiles a(sb)=[[/etc/default/ssh,true]]`;
* `ExecStartPre=/usr/sbin/sshd -t`;
* `ExecStart=/usr/sbin/sshd -D $SSHD_OPTS`;
* `ExecStartPost` пуст, DropInPaths пуст, TriggeredBy пуст;
* `ssh.socket` inactive; active/running MainPID и ненулевой InvocationID;
* поддерживаемая namespace/sandbox конфигурация, общий mount namespace
  активатора, PID1 и работающего sshd.

Данные получены actual `readLaunchContract`, `SystemdActivation::preflight`,
`openAbsolute`, `verifyTree`, `requireSafePublicationParent`, `SshConfigAudit`.
Production читает типизированные properties через direct root PID1 bus.
Harness делает fixture-only trust setup systemctl после environment guard.
Public API, trust provisioning FIC и политики не изменены.

Полный внутренний launch contract сравнивается самим активатором на всех прежних
фазах; harness дополнительно сравнивает before/after и сохраняет SHA, не значения
произвольного environment. Ошибка диагностического post-probe записывается
отдельно и не подменяет ActivationResult.

## 4. Exact distro source evidence

Получены официальные .dsc и перечисленные ими archives, проверены size/SHA256,
`dpkg-source -x` применил Debian patch series. В evidence сохранены SHA каждого
архива/patch и полный series. Ссылки:

* [Debian12 source descriptor](https://deb.debian.org/debian/pool/main/o/openssh/openssh_9.2p1-2+deb12u10.dsc),
  SHA `af8cfb3ce783604abd28183a52aa0bde8c6bc603cc35758035db48d1dac5f2e2`.
* [Debian13 source descriptor](https://deb.debian.org/debian/pool/main/o/openssh/openssh_10.0p1-7+deb13u4.dsc),
  SHA `73fed3fd77d60925ed342bcb0afd3c037e4ea0d39333107bf617aa90f859910f`.

Signer public key на исследовательском host отсутствует: PGP .dsc signature
**NOT_VERIFIED**. HTTPS и declared archive hashes проверены; это не заменяет
полную archive signing-chain verification и не доказывает неизменность executable
против привилегированного writer во время операции.

Проверяемые точки в распакованных patched sources:

| Debian | Parse → listen → READY |
|---|---|
| 12 | `debian/rules:83 --with-systemd`; `systemd-readiness.patch` + `systemd-socket-activation.patch`; `sshd.c:1824/1826` load/parse, `:2139` server_listen, `:2164` sd_notify READY |
| 13 | `configure.ac:976–977` SYSTEMD_NOTIFY/SOCKET_ACTIVATION; `sshd.c:1638/1640` load/parse, `:1951` server_listen, `:1961` platform_post_listen; `openbsd-compat/port-linux.c:407` READY |

В обычном standalone listener mode READY следует за initial parse и listen.
Оно не доказывает policy semantics, полную dependency closure или успешный login.
Exact systemd sources того же userspace: `replace_env_argv` в
`src/basic/env-util.c` (252.39:694/716; 257.13:888/918) разбивает `$SSHD_OPTS`
с unquoting. Использован native systemd expansion, не Python/shlex/shell emulator.

## 5. Mount topology и границы provisioning

`/proc/1/mountinfo`, `/proc/self/mountinfo`, `findmnt`, UID/GID/mode/xattr names
и namespace observations сохранены в ignored `build-openssh-native/<profile>/evidence`.
Sanitized summary входит в JSON evidence.

| Parent | Debian12 | Debian13 |
|---|---|---|
| `/etc/ssh`, `/etc/default` | `/`, private, overlay | `/`, private, overlay |
| `/run/fic` / будущий workspace | `/run`, private, tmpfs | `/run`, private, tmpfs |

На первоначальных target нет foreign mount. Runtime directory создаётся как
обычный root-controlled каталог. **Mount topology не менялась ради PASS**:
дополнительные private boundaries не требовались, `/` не make-private.
Workspace tmpfs/binds создаёт и снимает production activator.

Для обычного shared-root хоста safe provisioning новых boundaries **не доказан**:
`BLOCKED_BY_MOUNT_TOPOLOGY`. Bind под shared parent, затем make-private, не даёт
доказательства отсутствия первоначального propagation. Такой эксперимент на
`/etc/ssh`, `/etc/default`, `/run/fic` не выполнялся. Native regression gate
повторяет peer-namespace tests: shared/shared-slave refusal до mount и отсутствие
peer mounts при **заранее** подготовленных private/non-shared-slave boundaries.
Это не SSH-specific provisioning обычного shared-root хоста. Нового provisioning
или изменения глобальной host propagation нет.

## 6. Controlled inputs и воспроизводимый metadata blocker

Основной положительный request:

1. `/etc/ssh/sshd_config`, File + SHA;
2. `/etc/ssh/sshd_config.d`, Directory + exact empty manifest;
3. `/etc/default/ssh`, File + SHA;
4. `/etc/ssh/ssh_host_ed25519_key`, File + SHA, mode0600;
5. соответствующий `.pub`, File + SHA.

Все root-owned; main/env/pub mode0644, directory0755; никаких symlink/ACL/labels.
Positive opts — строго известный `SSHD_OPTS=`. Main использует только loopback,
Port2222, `VersionAddendum FIC_VERIFIED`, явный test HostKey; auth/PAM fixture
отключены. Пустой Include directory защищает также отрицательное множество glob.
Не включаем весь `/etc/ssh` с неиспользуемыми private files в manifest.

### OverlayFS copy-up: реальный отдельный blocker

Исходные lower-layer main/env/directory: xattr size query0, names empty.
После обычного truncate/copy-up main: `flistxattr(fd,nullptr,0)=23`, но bounded
`flistxattr(fd,buffer,4096)=0`, names empty. Аналогично после добавления Include
в stock lower-layer directory. Actual preflight возвращает
`UnsupportedConfiguration: extended attributes/ACL/labels require an unsupported snapshot attribute contract`.

Причина в сочетании `noXattrs()` (positive size query трактуется как наличие
attributes) и [WSL kernel OverlayFS `ovl_listxattr`](https://raw.githubusercontent.com/microsoft/WSL2-Linux-Kernel/linux-msft-wsl-6.6.87.2/fs/overlayfs/inode.c):
size-only путь возвращает размер до фильтрации private overlay attributes;
буферный путь фильтрует их. Это согласуется с наблюдениями; наличие реальных
пользовательских ACL/labels этим не доказано. Сам отказ fail-closed сохранён.

Для baseline main/env **явно создаются заново из synthetic template**, а
изначально пустой stock Include directory не меняется. Это проходит full preflight
без topology change. Дальнейшие nonempty Include/concurrency tests используют
**новый** `/etc/ssh/fic-native-inputs` с exact manifest: иначе подготовка stock
directory вызывает copy-up blocker. Начальный empty-stock baseline и оба
copy-up отказа сохранены отдельно. Ничего не фильтруется в production, xattrs
с реальных inputs не удаляются. Это fixture restriction, не production workaround.

## 7. EnvironmentFile / argv audit

Positive EnvironmentFile присутствует, SHA проверяется, optional-present покрыт
точным File target. Optional-absent и uncovered file получают Unsupported до
restart. Изменение SSHD_OPTS после построения reference даёт checksum/source
verification refusal при неизменном unit.

Реальные отдельные probes:

* `-f /run/fic-openssh-work/external.conf`: новый sshd использует EXTERNAL/2224;
* два `-oVersionAddendum=...`: наблюдается первое значение CLI_FIRST;
* quotes вокруг `VersionAddendum=CLI SPACE` и два `-p`: native expansion
  сохраняет значение с пробелом, слушаются 2225 **и** 2226;
* неизвестный `-Z`: реальный restart failure; stock ExecStartPre проверяет main
  **без SSHD_OPTS** и не доказывает корректность итогового CLI config path;
* `-f` FIFO: новый MainPID открывает файл, остаётся activating/start, READY нет.

Непустой/неизвестный SSHD_OPTS semantic guard стенда отклоняет консервативно.
Он не парсит shell/systemd. Generic activator защищает такие env bytes и может
дать Success; это ожидаемое доказательство недостаточности A+B для SSH compliance.
Поздний `/proc/MainPID/cmdline` не использован как исходный argv: OpenSSH меняет
process title. Полный захват initial execve argv **NOT_TESTED**.

## 8. Include closure audit

Baseline — основной файл + пустой защищённый stock glob directory. В последующих
fresh-tree сценариях защищаются nested Include, files вне `*.conf` и Include под
Match; отдельный `sshd -T -C` подтверждает интерпретацию test context.
Это не проверка Match enforcement на authenticated connection.

Fixture-only analyzer допускает ограниченную literal absolute Include grammar,
проверяет metadata/coverage и **родитель wildcard**, даже при GLOB_NOMATCH.
Symlink target не раскрывается, неизвестная quoting/recursive grammar отклоняется.
Он не объявлен универсальным parser OpenSSH. `SshConfigAudit::sourceIdentity`
переиспользован как actual FIC graph fingerprint; сам по себе он не закрепляет
отрицательное множество glob и не заменяет guarded directory manifest.

Exact `servconf.c` (12:2190/2239+; 13:2345/2394+) загружает и кеширует Include
contents, включая placeholder для отсутствующего match; Match state сохраняется
вокруг вложенного parse. Для runtime recursion/connection повторного parse
общая семантическая гарантия здесь не заявлена.

Контрпримеры:

* Include вне request: generic Success, listener/banner EXTERNAL — C FAILED;
* незащищённый glob parent: callback создаёт новый файл до restart, generic
  Success, banner GLOB — C FAILED;
* защищённый parent: запись через preopened original directory FD создаёт hidden
  match; runtime видит прежний manifest, но после cleanup original содержит
  новый файл — persistent reference FAILED;
* symlink Include в exact manifest: generic Unsupported до restart.

Штатный vendor-owned Include не входил в baseline (Debian stock directory пуст).
Его универсальная поддержка/authority, arbitrary external graphs и provider
symlink compatibility **NOT_PROVEN/NOT_TESTED**, не выведены из synthetic tests.

## 9. Positive public activation и network observations

Обе Debian-среды: `status=Success`, `primaryStatus=Success`,
`readinessConfirmed=true`, `cleanupErrors=[]`, `residualPaths=[]`.
Новые MainPID/InvocationID; сохранены process starttime и общий namespace.
Полный launch contract before/after совпадает. Остатков fic-vcsa mounts нет,
config/reference bytes/manifests после normal cleanup совпадают. Служба остаётся
active/running и обслуживает loopback после снятия защиты.

Наблюдаются stock server identifications с `FIC_VERIFIED` на 127.0.0.1:2222,
отправлен synthetic SSH client identification, получен реальный
`SSH_MSG_KEXINIT (20)`. Это **не завершённый KEX и не login**. `ss -lntp`
сопоставляет listener с процессом; `sshd -T/-T -C` — отдельная вспомогательная
диагностика, не самостоятельное доказательство running bytes.

В основном positive нет test hooks. A опирается на реальные production
verifyTree/RO/identity/observer проверки. Дополнительный real-sshd `ro-write`
с hooks сохраняет actual published mount/inode IDs всех пяти targets,
повторно проверяет manifests и получает EROFS при writable open.

## 10. Proof matrix и negative/concurrency результаты

Обе Debian-среды завершили **29/29 ожидаемых сценариев**, без harness failures
и skips. Отказы ниже — ожидаемые результаты тестов, не FAIL самого test runner.

* **A**: защита **переданных** inputs в ограниченном observation window.
* **B**: новый проверенный sshd READY/process/launch contract.
* **C**: полная ожидаемая effective SSH configuration semantics — **NOT_PROVEN**
  на положительных сценариях; **FAILED** при наблюдаемом semantic контрпримере.
* **Selected** (`C_selected`): выбранные ожидаемые port/version свойства известной
  fixture, при доверии конкретной сборке и ограниченной closure. Его PROVEN
  не заменяет C; для Match runtime выбранная проверка также недостаточна.
* **P**: совпадение persistent reference bytes/exact manifests после cleanup;
  не полный metadata/SSH policy audit. При residual mount — NOT_PROVEN до
  отдельного administrator cleanup, поскольку original скрыт.

PROVEN / FAILED / NOT_PROVEN в полной scenario matrix ниже одинаковы на Debian12
и Debian13. `—` в P означает отдельная persistent оценка не собиралась для
исходного invalid input. Общая SSH semantic closure — NOT_PROVEN.

| Сценарий | Activation status | A | B | C | Selected | P |
|---|---|---|---|---|---|---|
| baseline-public-stock-ssh | Success | PROVEN | PROVEN | NOT_PROVEN | PROVEN | PROVEN |
| nested-and-Match-Include | Success | PROVEN | PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |
| duplicate-directive-first-wins | Success | PROVEN | PROVEN | NOT_PROVEN | PROVEN | PROVEN |
| missing-Include-with-protected-negative-set | Success | PROVEN | PROVEN | NOT_PROVEN | PROVEN | PROVEN |
| symlink-Include-input | UnsupportedConfiguration | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |
| wrong-reference-sha | ChecksumMismatch | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | FAILED |
| missing-required-file | ChecksumMismatch | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | — |
| optional-env-absent | UnsupportedConfiguration | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | FAILED |
| uncovered-env | UnsupportedConfiguration | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |
| symlink-main | UnsupportedConfiguration | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | — |
| SSHD_OPTS-changed-since-reference | UnsupportedConfiguration | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | FAILED |
| uncovered-external-Include | Success | PROVEN | PROVEN | FAILED | FAILED | PROVEN |
| unguarded-new-glob | Success | PROVEN | PROVEN | FAILED | FAILED | PROVEN |
| guarded-new-glob | Success | PROVEN | PROVEN | NOT_PROVEN | PROVEN | FAILED |
| CLI-f-external | Success | PROVEN | PROVEN | FAILED | FAILED | PROVEN |
| CLI-o-first-wins | Success | PROVEN | PROVEN | FAILED | FAILED | PROVEN |
| systemd-real-quoted-expansion | Success | PROVEN | PROVEN | FAILED | FAILED | PROVEN |
| sshd-t-and-real-restart-failure | RestartFailed | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |
| real-sshd-argv-restart-failure | RestartFailed | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |
| contract-before | InterferenceDetected | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |
| contract-after | InterferenceDetected | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |
| inode | InterferenceDetected | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |
| aba | InterferenceDetected | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |
| ro-write | Success | PROVEN | PROVEN | NOT_PROVEN | PROVEN | PROVEN |
| original-write | Success | PROVEN | PROVEN | NOT_PROVEN | PROVEN | FAILED |
| busy | CleanupFailed | PROVEN | PROVEN | NOT_PROVEN | PROVEN | NOT_PROVEN |
| foreign | CleanupFailed | PROVEN | PROVEN | NOT_PROVEN | PROVEN | NOT_PROVEN |
| crash | SIGKILL | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN |
| new-real-sshd-blocked-before-READY | TimedOut | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | NOT_PROVEN | PROVEN |

Неравенство PID/InvocationID дополнительно утверждается harness для primary
Success; systemd process/root/namespace/starttime подтверждает сам activator.
Ни is-active, ни `sshd -T`, ни banner отдельно не используются как полный proof.

## 11. Failures, concurrency и cleanup

* Bad SHA, отсутствующий main, symlink main/Include, env absence/coverage/source
  change отказали до restart. Syntax-invalid main и invalid CLI реально
  приводят к RestartFailed, без readiness и без residual mounts.
* Manager.Environment меняется на Watching либо RestartQueued; actual launch
  comparison даёт InterferenceDetected без записи unit/drop-in.
* Перед публикацией reference config inode заменяется атомарным rename в том же
  filesystem — InterferenceDetected. Cross-filesystem rename первоначально был
  дефектом harness и исправлен; он не принят как успешный race test.
* Original FD write после публикации: primary Success, runtime FIC_VERIFIED/2222;
  после cleanup отдельный `sshd -T` видит изменённую original конфигурацию.
  Persistent FAILED — не rollback, не ошибка RO snapshot.
* Mount bind/unmount ABA до restart: sticky observer даёт InterferenceDetected.
  Это не обещание обнаружить любой privileged/alternate-namespace ABA.
* EBUSY: реальный открытый snapshot FD в BeforeCleanup;
  `status=CleanupFailed`, `primaryStatus=Success`, readiness=true. Чужой overlay
  перед cleanup также сохранён, не размонтирован компонентом, status CleanupFailed.
* SIGKILL после publication оставляет mounts; повторный activate во всех трёх
  случаях даёт ResidualMounts без adoption/removal. Только fixture admin затем
  убирает известные mounts; bytes после admin cleanup проверены относительно
  **прежнего** reference, не новой вычитанной baseline.
* FIFO-writer и новая реальная sshd reader синхронизированы pipe barrier, без
  случайного sleep. Сохранены новый MainPID и activating/start; через 5-секундный
  deadline — TimedOut, readiness=false, cleanup без residual mounts.

Последний cleanup PASS, восстановленный `sshd -t` PASS, stock unit hashes прежние;
runtime контейнеры удалены EXIT trap. Test admin cleanup не меняет исходный
ActivationResult и не является production crash recovery.

## 12. Regression matrix и full validation

| Gate | Debian12 | Debian13 | Ubuntu24.04 | Ubuntu26.04 | ALT p11 |
|---|---|---|---|---|---|
| Real OpenSSH | 29 PASS / 0 FAIL / 0 SKIP | 29 PASS / 0 FAIL / 0 SKIP | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Existing standalone | 132 PASS / 0 FAIL / 0 SKIP | 132 PASS / 0 FAIL / 0 SKIP | 132 PASS / 0 FAIL / 0 SKIP | 132 PASS / 0 FAIL / 0 SKIP | 132 PASS / 0 FAIL / 0 SKIP |

Standalone gates сохраняют EnvironmentFile order/duplicates/absence, mount
propagation/peer tests, RO/ABA, READY/deadline, actual config FD attestation,
EBUSY/foreign/SIGKILL regressions. Первый нагруженный Ubuntu26 прогон корректно
отказал на mount event в positive case; свежий финальный прогон PASS. Источник
постороннего event не атрибутирован. Observer/assertions не менялись, production
retry не добавлен. Все пять userspaces используют одно WSL2-ядро.

Полная Debian12 configure/build PASS. Полный CTest: **187 PASS / 0 FAIL /
1 ожидаемый native opt-in SKIP**, 188 total, 177.92s. Новый read-only
`openssh_native_harness_contract` PASS; финальный отдельный повтор этого CTest
после harness edits PASS. Privileged evidence получено runner-ами выше, не skip.

Full command в Docker `fic-ssh-audit:debian12`: source RO, own
`build-env-full-debian12` volume, no network, DAC_OVERRIDE/DAC_READ_SEARCH dropped,
container-local safe.directory=/src, `cmake -S /src -B /build
-DFIC_TARGET_PLATFORM=debian-12`, `cmake --build /build -j6`,
`QT_QPA_PLATFORM=offscreen ctest --test-dir /build --output-on-failure`.
Build-root ownership восстановлен trap. Логи — ignored `build-openssh-native/logs`.

## 13. Что установлено и что остаётся блокером

1. Реальная Debian stock service совместима с generic lifecycle на испытанной
   private-root topology и поддерживаемых fresh input metadata. Debian12
   usr-merge reader работает, полный preflight возможен.
2. **OverlayFS copy-up xattr sizing** — воспроизводимый compatibility blocker.
   Это отдельная задача компонента, не исправление SSH или упаковки.
3. **SSH closure/argv authority** — semantic blocker production integration:
   generic Success намеренно не проверяет Include/CLI policy compliance.
4. **Shared-root provisioning** — не решён. Нужна отдельная развёртываемая
   архитектура private boundaries без первоначального peer propagation.
5. **Persistent/runtime divergence** реальна. Успешный защищённый запуск не
   устанавливает permanent protection оригиналов и не обосновывает rollback.

## 14. Следующая архитектурная задача

Предлагается отдельное ТЗ на **SSH-specific verified activation adapter**,
до подключения к policies:

* authority/reference брать из существующей policy transaction/ownership, а не
  объявлять текущие прочитанные bytes эталоном;
* для первой версии можно явно ограничить opts известным пустым значением;
  произвольный -f/-o разрешать только после доказательства effective input set;
* переиспользовать SshRuntime/SshConfigAudit/SshInputAuthority/SshConfigSyntax,
  но дополнить proof отрицательных glob sets, nested/Match/external Includes,
  symlink/vendor ownership и trusted executable/input closure;
* не интерпретировать systemd expansion упрощённым shell parser и не использовать
  setproctitle-изменённый cmdline как первоначальный argv;
* доказывать selected effective policy через source + pinned bytes + readiness
  + независимые runtime observations, с явным отказом при неизвестной семантике;
* разделить saved/persistent и applied/runtime, cleanup failure и residual state.

До этого полезно отдельное узкое исправление noXattrs: исследовать **bounded
actual-name retrieval**, errno/ERANGE/size bounds и стабильность descriptor metadata;
положительный size-only ответ не должен автоматически означать видимые attrs.
Сохранить строгий отказ на реально nonempty ACL/labels/xattrs и ошибки, добавить
copy-up regression. Не вводить whitelist удаления/игнорирования реальных attrs.
В текущем коммите такого production исправления нет.

## 15. План будущей связи с apply/rollback

Сначала отдельно подтвердить adapter contract/тесты. Затем существующая
SshConfigTransaction/MutationJournal сохраняет единственное ownership и CAS;
adapter строит доказанный request и выполняет runtime promotion через public
activator. Успех application — только при нужном C proof, подтверждённом READY
и успешном cleanup. Persistent save и runtime result возвращаются раздельно.

При failure не восстанавливать файлы без ownership/CAS proof и не выдавать saved
за rolled back. Для reactivation прежнего состояния нужна такая же проверка
closure/снимка/readiness; residual mounts требуют явного administrator recovery,
не автоматического adoption. Uninstall/release остаются в существующем контракте.
Это план, **ни один из этих production callers/контрактов здесь не менялся**.

## 16. NOT_TESTED / NOT_PROVEN

* Собственные Debian kernel/VM/physical boot; shared-root OpenSSH deployment.
* Ubuntu/ALT real SSH activation (их socket/notify препятствия вне этапа).
* Полный KEX, host-key/client verification, auth/PAM/root recovery и live login.
* Match policy enforcement на authenticated connection, произвольные Include/
  argv/vendor symlink graphs, полный input/executable/library dependency proof.
* Enforcing SELinux/ACL provider semantics и иные kernels/filesystems.
* Непрерывная защита после cleanup, произвольный CAP_SYS_ADMIN/hidden launch/unit
  ABA, ранее описанные alternate-namespace observer blind spots.
* PGP descriptor signing-chain verification и повторная сборка binary из source.

## 17. Изменённые области

Только `tests/integration/verified_config_service/openssh_native/`, CTest registration,
этот report/evidence и HANDOFF. Production `fic/`, SSH policies/runtime/transaction,
ownership, rollback, MutationJournal, штатные units и packaging не изменены.
Никаких автоматических миграций/постоянных drop-in/production adapters нет.

## 18. Артефакты и критерий завершения

JSON evidence содержит actual результаты обоих Debian runs, включая поля
ActivationResult, A/B/C/Selected/P, normal/fault observations, metadata refusal и sources.
Evidence привязан к hash runner identity конкретного контейнера; fault injection
с чужим run_id отвергнут до записи отчёта (PASS), старый успешный runtime не
принимается за новый. Raw mountinfo, build/runtime logs и caller before/after checks остаются в ignored
build directory, не требуют ключей для воспроизведения.

Критерий этапа выполнен: установлено, **какие свойства настоящего OpenSSH**
подтверждаются Success на испытанной конфигурации, приведены действующие
контрпримеры более сильному утверждению и выделены отдельные следующие задачи.

## Bounded xattr follow-up

Этот раздел — новый замер поверх `692d34a6f6b3595e088b30b35ced4193b6be77fd`.
Разделы 1–18 и исходный JSON evidence выше оставлены как исторический результат:
их fresh-file/new-Include-directory ограничения описывают прежний код.
Новое [сокращённое evidence](verified-config-xattr-evidence.json) содержит
copy-up metadata, public ActivationResult, process identities, hashes образов,
названия/результаты сценариев и standalone totals. Полные текущие безопасные
результаты собирает прежний `collect-evidence.py`, теперь с проверкой 30 случаев,
штатного Include path и обязательной успешной copy-up activation.

### Исправление и security review

Production diff ограничен `VerifiedConfigMountSupport.cpp/.h`: вместо
`flistxattr(fd, nullptr, 0)` используется фактический список в фиксированном
буфере 65536 байт. Проверяется достоверность контекста: root и эффективный
CAP_SYS_ADMIN в initial user namespace. Положительный результат любого имени,
ошибка, переполнение или недостаточная видимость не принимаются за отсутствие.
Исключение ENOTSUP удалено. Второе перечисление выполняется после чтения;
ctime/mtime/inode/mount ID, source CAS и остальные metadata checks сохранены.

Это не поддержка сохранения xattrs/ACL/security labels. Новые реальные
`user.*`, `trusted.*`, access/default POSIX ACL и `security.capability`
на файлах/каталогах OverlayFS и tmpfs отклонены до собственного mount.
Пустое значение и длинный список имён также отклонены. Unit injection проверяет
все перечисленные в ТЗ ошибки, неизвестную errno, границы 65536/65537,
отсутствие size-query/retry и отказ даже для явно возвращённого имени
`trusted.overlay.origin`; production не фильтрует имена и не выводит их.

Повторная проверка обнаруживает появление/замену атрибутов и изменение ACL
после первого перечисления. Детерминированные transient add/remove проверки
подтверждают отказ по ctime при пустом итоговом списке; отдельные случаи
проверяют independent content change и pinned FD при замене pathname.
Для ctime-тестов используется timerfd-барьер с учётом coarse clock. Обнаруженная
при разработке ошибка слишком раннего тестового барьера исправлена в harness,
не ослаблением production-проверок. Ни эти тесты, ни два перечисления не
доказывают атомарность против скрытого privileged/coarse-clock ABA.

Полный разбор API, namespaces, LSM, доверия к filesystem provider, bounds и
остаточной гонки приведён в [контракте компонента](verified-config-service-activator.md#bounded-xattr-validation-follow-up-к-692d34a).
Mount publication/readiness/cleanup не менялись; ложный Success при cleanup
error по-прежнему запрещён. SSH policies, apply/rollback, ownership и
MutationJournal не изменены.

### Основной acceptance gate

Во всех четырёх Debian/Ubuntu userspaces штатные lower-layer file и directory
показали один результат на общем WSL kernel:

| Объект | До copy-up: size/actual | После обычной записи: size/actual | Итог |
|---|---:|---:|---|
| `/etc/ssh/sshd_config` | 0 / 0 | 23 / 0 | verifyTree + RO snapshot PASS |
| `/etc/ssh/sshd_config.d` | 0 / 0 | 23 / 0 | exact nonempty manifest + RO snapshot PASS |

Это kernel-фильтрация при actual listing, а не разрешение FIC пропускать
реально возвращённые overlay names. Сравнение исходников WSL/upstream и
причина расхождения описаны в контракте компонента.

**Реальный OpenSSH Debian 12 и 13:** каждый **30 PASS / 0 FAIL / 0 SKIP**.
Штатный copied-up `sshd_config` сохраняется при reset, EnvironmentFile пишется
на месте. Все Includes используют штатный `/etc/ssh/sshd_config.d`; свежего
`fic-native-inputs` больше нет. Новый отдельный positive со штатным непустым
Include-каталогом и точным manifest использует публичный activate(), настоящий
ssh.service без override, новый MainPID/InvocationID, READY, успешный cleanup
без residual mounts. Unit bytes неизменны, восстановленный `sshd -t` PASS,
caller SSH paths не изменены. Все прежние негативные и concurrency assertions
сохранены, включая ожидаемые CleanupFailed/ResidualMounts в fault cases.

A/B доказываются в принятой модели; full SSH C по-прежнему NOT_PROVEN на
обычных positives и FAILED для сохранённых semantic counterexamples.
Полный KEX, authenticated Match/PAM/login и Include/argv authority closure
не стали доказанными вследствие исправления xattr.

### Regression matrix

Запущены существующие runners с `fic-ssh-audit:<tag>`:

| Native standalone | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| Debian 12 | 201 | 0 | 0 |
| Debian 13 | 201 | 0 | 0 |
| Ubuntu 24.04 | 201 | 0 | 0 |
| Ubuntu 26.04 | 201 | 0 | 0 |
| ALT p11 | 200 | 0 | 1 |

ALT skip — отсутствует подходящий штатный пустой SSH Include fixture для
lower-layer copy-up пары; остальные xattr/ACL/security/capability/user-namespace
проверки ALT выполнены. Обязательный copy-up gate Debian 12/13 полностью PASS.
Metadata/manifests, EnvironmentFile, tmpfs RO, source CAS, mount ABA,
launch contract, READY/timeout, EBUSY/foreign/crash cleanup regression сохранены.

Логи: `build-verified-config/xattr-<tag>-final.log`,
`build-openssh-native/logs/xattr-debian{12,13}.log`; sanitized runtime evidence —
`build-openssh-native/<profile>/evidence/`. Это Docker userspace matrix на одном
`6.6.87.2-microsoft-standard-WSL2`, не пять native distro kernels.

ext4, XFS, enforcing SELinux и отдельные VM kernels — **NOT_TESTED**: подходящей
одноразовой VM нет, host block devices не создавались и не форматировались.
Успешные OverlayFS/tmpfs tests не считаются доказательством всех filesystems.

Полная Debian 12 configure/build: PASS. Полный CTest: **187 PASS / 0 FAIL /
1 ожидаемый native opt-in SKIP**, 188 total, 125.69 s
(`build-verified-config/xattr-full-debian12.log`). Native suite отдельно запущена
явно на всех пяти userspaces, поэтому opt-in skip не заменяет native evidence.
