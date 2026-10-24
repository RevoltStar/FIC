# SSH verified activation adapter v1

## Назначение и trusted reference

`fic/src/service/ssh/SshVerifiedActivationAdapter.h` — самостоятельный production
компонент, вызываемый Debian 12/13 и Ubuntu 24.04/26.04 SSH policy apply. Сам adapter не пишет
persistent конфигурацию, не получает ownership и не выполняет rollback/compensation.
`Ssh::apply()` отвечает за provenance, CAS/save и journal finalization.

```cpp
using namespace fic::service;
using namespace fic::service::ssh;
SshVerifiedActivationRequest request;
request.reference.unit = "ssh.service";
request.reference.paths = callerAuthorizedFilesAndExactDirectoryManifests;
request.reference.timeout = std::chrono::seconds(10);
request.policies = {{"ssh_root_login", "no"}, {"ssh_pubkey_auth", "yes"},
                    {"ssh_use_pam", "yes"}, {"ssh_max_auth_tries", "3"},
                    {"ssh_port", "2222"}};
auto result = SshVerifiedActivationAdapter::activate(request);
```

Caller предоставляет **ожидаемые**, уже авторизованные SHA-256 и exact manifests.
Adapter сверяет наблюдаемые байты с ними; не вычисляет reference из текущего
файла для автоматического принятия его как желаемого. Считывание байтов для
сверки не является enrollment. В native harness reference формируется из
заранее заданной synthetic fixture — только test provisioning.

Trusted reference, observed state и FIC ownership различаются. `captureReference()`
читает root-controlled штатные источники через descriptors, проверяет supplied SHA
основного файла из CAS snapshot, exact manifests и metadata повторным capture.
Это operation-local reference чужих доверенных входов, а не enrollment их как
желаемых policy values или ownership. Желаемое значение приходит из policy config;
ownership доказывается отдельно managed blocks и `DaemonMutationJournal` **до**
построения reference. После save разрешается изменение только основного файла,
закреплённое installed-state receipt; все чужие inputs сохраняют прежние SHA/metadata.
Полный publication environment preflight выполняется read-only до Prepared/save.

Проверяются полный набор путей, canonical lowercase SHA, дубликаты/пересечения,
manifest, лимиты generic activator и identifiers/значения выбранных политик.
Неполный reference отклоняется целиком. Общие snapshot bounds и metadata
контракт остаются [прежними](verified-config-service-activator.md).

## Поддерживаемый launch profile

Build profiles **Debian 12/13 и Ubuntu 24.04/26.04**, подтверждённые `/etc/os-release`.
Ниже описан Debian service profile. Ubuntu использует отдельный закрытый
[socket profile](ubuntu-ssh-socket-activation-spec.md) того же engine, допускающий
inactive service при persistently enabled/active socket и проверяющий listener/FD.
ALT остаётся Unsupported в adapter; legacy policy lifecycle не меняется.
Подготовка private boundaries не входит в adapter. На shared publication parent
без безопасной границы generic engine продолжает отказывать.

Используются `SystemdActivation::preflight()` и существующий typed D-Bus
`readLaunchContract`, включая canonical identity, triggers, namespace/sandbox,
loaded values и unit-source fingerprints. В v1 дополнительно требуются:

* `ssh.service`, active/running, notify/main, без pending job и socket triggers;
* vendor FragmentPath `/lib/systemd/system/ssh.service` либо
  `/usr/lib/systemd/system/ssh.service`; ограниченные drop-ins описаны ниже;
* exact argv `ExecStart=/usr/sbin/sshd -D $SSHD_OPTS`, без execution flags;
* exact `ExecStartPre=/usr/sbin/sshd -t`, без flags;
* пустые ExecCondition/StartPost/Stop/StopPost, Environment/PassEnvironment/
  UnsetEnvironment;
* единственный typed EnvironmentFiles entry `[/etc/default/ssh, optional=true]`.
  Файл всё равно обязан существовать и иметь явный File reference;
* stock root credentials: пустые User/Group/SupplementaryGroups;
* root-controlled sshd, разрешённый `PlatformExecutableResolver`, с заранее
  доверенным hash в `CommandHashStore`. Adapter сам hash не enroll-ит.

Профиль строже произвольной Debian-конфигурации. Допустимы только drop-ins
`/etc/systemd/system/ssh.service.d/*.conf` с `[Unit] Description=` и
`[Service] CPUWeight=1..10000`. Их содержимое связано с unit-source fingerprints;
continuations, substitutions и неизвестные директивы отклоняются. Дополнительные
hooks/envfiles/options и override unit Unsupported. ExecReload не вызывается;
обычного reload/restart fallback нет.
Initial argv не извлекается из изменяемого process title `/proc/PID/cmdline`.

Manager.Environment не разрешается произвольно. Допустимы только отдельные
точные assignments: LANG=C/C.UTF-8/C.utf8, LC_ALL=C/C.UTF-8 и PATH из трёх
проверенных вариантов:

```
/usr/sbin:/usr/bin:/sbin:/bin
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
```

Последний — фактически измеренный штатный usr-merge PATH Debian 13. Любой
другой key/value, в частности SSHD_OPTS/LD_PRELOAD/неизвестная locale, означает
отказ. Generic engine закрепляет весь launch contract, не только этот subset.

### EnvironmentFile

Поддерживается ровно один assignment `SSHD_OPTS=` с необязательными leading и
trailing spaces/tabs, пустые строки и полнострочные `#` comments. До 64 KiB.
Пустые `SSHD_OPTS=""` и `SSHD_OPTS=''` также разрешены. Никаких других
assignments, duplicate assignments, непустого quoting, continuation, CR,
NUL или дополнительных аргументов.
Это сознательный classifier небольшого языка, не копия systemd env parser.
`-f`, `-o`, `-p` и неизвестные opts отклоняются **до restart**.

## Include closure и отрицательное множество

`SshVerifiedInputClosure` использует `parseSshConfigLine` только внутри строгого
ASCII subset. Корень — `/etc/ssh/sshd_config`. Разрешены:

* literal normalized Include внутри `/etc/ssh/sshd_config.d/`, без symlink, traversal, quoting/escapes;
* relative Include разрешается относительно `/etc/ssh` и обязан остаться внутри `.d`;
* только glob `*.conf` внутри поддерживаемой `.d` области, с wildcard лишь в basename;
* вложенные/несколько/повторные Include в исходном порядке, до глубины 16,
  256 file visits, 65536 lines и 8192 bytes/line;
* пустой glob, если его **корень каталога** является явным Directory target с
  exact manifest; отсутствующий literal — только с таким защищённым parent.

Glob не выполняется по изменяемому дереву. Кандидаты выбираются из уже
проверенных bytes/manifests в ASCII lexical order; dotfiles исключаются, как у
проверенного OpenSSH/glob без GLOB_PERIOD. Защищается целый каталог, включая
negative set, а не только текущие matches. При original-FD добавлении нового
файла в исходный каталог опубликованный RO directory не меняется; после cleanup
P выявляет появившийся файл. Защита отдельными File targets вместо Directory
не допускается для glob даже при пустом результате.

Caller не может расширить Include boundary дополнительными trusted directories.
Путь проверяется до expansion, даже при пустом glob или Include внутри Match. Missing Include без
выразимой защиты namespace, directory-glob, `?`, произвольные wildcard patterns,
`~`, `%`, не-ASCII paths, неоднозначный syntax и рекурсия отклоняются.
Placeholder-файлы и автоматические исправления отсутствуют.

Whitelist остальных директив v1: PermitRootLogin, PubkeyAuthentication, UsePAM,
MaxAuthTries, Port, ListenAddress, AddressFamily, HostKey, PidFile, LogLevel,
VersionAddendum, PermitTTY, PasswordAuthentication, KbdInteractiveAuthentication,
PrintMotd, X11Forwarding, AcceptEnv, Subsystem, AuthorizedKeysFile, UseDNS,
PermitEmptyPasswords, StrictModes, LoginGraceTime. Native sshd дополнительно
проверяет их значения/арность. Неизвестные directives отклоняются. Match с первым
критерием all/User/Group/Address/LocalAddress/LocalPort/Host классифицируется
консервативно: любой subsequent conditional assignment выбранной директивы
отклоняется; контекст разделяется с Include. Посторонние директивы внутри Match
не запрещают другую выбранную политику. Match exec/unknown criteria отклоняются.
Это не доказательство всех Match contexts через несколько `-T -C` probes.

Каждый explicit HostKey и companion `.pub` должен иметь reference coverage.
При отсутствии HostKey поддержан полный штатный Debian default set: RSA, ECDSA
и ed25519 по `/etc/ssh/ssh_host_{rsa,ecdsa,ed25519}_key`, вместе с `.pub`.
Отсутствие любого reference этого набора отклоняется; metadata private keys не
ослаблены. Набор подтверждён реальным sshd -T на Debian12/13. HostKeyAgent, HostCertificate и
прочие неописанные launch/config dependencies v1 не принимает. Secret bytes
не включаются в diagnostics/evidence. Private HostKey должен быть regular, UID 0,
с mode ровно 0600 или 0400; group/other, special bits, symlink, xattr/ACL
не допускаются. Это отдельное preflight-ограничение, даже при совпадении SHA.
Companion `.pub` не считается private key; 0644 разрешён.

## Selected policy proof

Классификация переиспользует `sshPolicyDirectiveSemantics()` и
`sshPolicyDirectiveKeyword()`. Значения соответствуют существующим FIC policy types:

| Identifier | Reference | Проверка |
|---|---|---|
| ssh_root_login | no / prohibit-password / forced-commands-only | Scalar first-wins |
| ssh_pubkey_auth | yes | Scalar first-wins |
| ssh_use_pam | yes | Scalar first-wins |
| ssh_max_auth_tries | 1–5 | Scalar first-wins |
| ssh_port | 1–65535 | Единственный ожидаемый effective port; ListenAddress не задаёт другой порт |

Numeric reference — canonical decimal без leading zero. Нужна непустая selection;
неизвестная политика или будущая политика без явного v1 contract — Unsupported.
Adapter не применяет политику, даже если она NonCompliant.

Используется `SshRuntime::policyValueCompliance()`, который вызывает тот же
`verifyLoadedConfiguration`, что `verifyPolicyValue()`, сохраняя Unknown отдельно
от NonCompliant. Проверка syntax/effective state — настоящий trusted `sshd -T`
с default config path, clear environment, C locale, bounded output/deadline;
никакого invented `-f` или CLI override. `SshConfigAudit`/trustedSshInput
переиспользуются через runtime и capture. `sourceIdentity()` изучен, но не
используется как closure proof: он не защищает negative glob set. Adapter
передаёт более полный reference/identity/manifest contract generic engine.

`sshd -T` **не единственное runtime доказательство**. Семантика сначала проверяется
read-only в preflight, затем повторяется на опубликованном защищённом snapshot
до restart. READY и идентичность нового процесса подтверждает generic engine;
ready callback сверяет `/proc/newMainPID/exe` с закреплённым доверенным sshd,
а также повторно проверяет executable hash/path identity. В native gate отдельный
loopback probe читает реальный banner/KEXINIT, а `ss -lntp` связывает конкретный
socket `127.0.0.1:2222` с **новым MainPID в той же строке**.

`C=Proven` означает ровно значения из request.policies при указанной грамматике,
launch и trusted-platform модели. Это не проверка всего OpenSSH, способов
аутентификации, ключей пользователей, PAM stack или всех контекстов подключения.

## Внутреннее расширение engine и TOCTOU

Публичный generic API с одними paths/digests не связывает внешний preflight
с launch contract и не позволяет доказать семантику внутри уже опубликованного
snapshot. Поэтому по согласованию добавлен **внутренний**
`VerifiedConfigActivationProof.h` / `activateWithProof()`:

1. Expected configuration сравнивается с новым generic preflight до mount.
2. Source root identities/mount IDs и полные tree attributes сравниваются с
   захваченными adapter expectations при generic capture до первого mount.
3. `published` callback проверяет closure/env и semantics после публикации RO,
   до restart. После callback engine повторяет проверку snapshot/observer.
4. `ready` callback проверяет executable нового READY MainPID; после него
   engine снова подтверждает snapshot, readiness и process identity.
5. Исключения callback используют тот же failure/cleanup путь. Callbacks не
   заменяют snapshot, restart, observer или cleanup.

Публичный `VerifiedConfigServiceActivator::activate()` остался без изменений;
оба entrypoint используют **один perform engine**. Adapter вызывает согласованный
internal entrypoint, а не буквально публичную функцию. Test hooks существуют
только при FIC_ACTIVATOR_TESTING и не предоставляют production bypass.

Исходные inode/metadata, exact manifests, env и launch contract привязаны к
одному request. Замена inode с тем же SHA, source mode drift, новый glob match
или изменение directory identity между preflight и engine дают отказ до restart.
Original-FD writes после публикации не меняют прочитанный snapshot и отражаются
отдельно в P. Общий timeout охватывает preflight, generic activation и P;
по истечении deadline общий Success не возвращается, runtime outcome сохраняется.

Это всё ещё последовательные проверки, не атомарный filesystem transaction.
Сохраняются документированные ограничения privileged/coarse-clock ABA, доверия
к kernel/filesystem/LSM и отсутствия постоянного наблюдения после return.

## Раздельные результаты A / B / C / P

| Поле | Смысл |
|---|---|
| inputs (A) | Proven только после подтверждённой защищённой активации |
| activation (B) | Исходный ActivationResult целиком, без изменения status/primaryStatus/READY/cleanup/residuals |
| semantics (C) | Proven / NonCompliant / NotProven / Unsupported для selection caller |
| persistent (P) | Проверенные после cleanup reference bytes/manifests и стабильные identity/metadata относительно operation baseline, отдельно от runtime |
| activationAttempted | Вызван generic engine; **не** утверждение, что restart уже запрошен |
| status | Success / Refused / ActivationFailed / RuntimeActivatedButPersistentDrift |

Общий Success требует успешного B/cleanup и A=C=P=Proven. При A/C Proven,
B Success и P NonCompliant возвращается RuntimeActivatedButPersistentDrift,
без попытки переписать диск, откатить или повторно reload-ить службу.
После CleanupFailed A/C могут остаться Proven, B сохраняет primaryStatus=Success,
но общий Success запрещён; P при недоступном исходном состоянии — NotProven.
Невозможность проверить P не превращается в доказанный mismatch.
После отказа до engine `activationAttempted=false`; B default не является
заявлением о фактической неудачной активации. Общий статус и flag обязательны
для интерпретации результата.

P — моментная проверка после cleanup, не постоянная compliance/ownership.
После её завершения администратор может снова изменить файлы или службу.

## Persistent metadata proof

Authorized caller reference (SHA/exact manifests) и operation baseline имеют разные
роли. Первый задаёт разрешённые bytes; immutable начальный `Capture` фиксирует
identity/metadata только на время операции и не становится эталоном или ownership.
После возврата generic engine и cleanup выполняется один bounded capture оригиналов:
FD-based `readTree` связывает bytes со stat до/после чтения и повторной проверкой
xattr; SHA/manifests проверяются именно для этих bytes. Root descriptor identity
сопоставляется с tree stat и повторно открытым видимым root. Наличие mount на
controlled target/внутри Directory запрещает принимать snapshot за original.

Сравниваются точные root/relative-path keys и состав maps; root mount ID, device,
inode, mode/type, UID/GID; для всех tree entries — device/inode, type и все mode bits,
UID/GID, nlink, size, mtime/ctime (секунды и наносекунды). Atime исключён, поскольку
само чтение меняет его. Existing no-xattr/ACL и trusted-parent проверки сохраняются.
Даже ужесточение mode, смена GID при root UID или новый inode с прежним SHA — drift.
При успешно наблюдаемом несовпадении P=NonCompliant. Ошибка чтения, unsupported
metadata/mount или deadline дают P=NotProven. В обоих случаях общий Success запрещён,
а B сохраняется полностью; при подтверждённом drift и успешном B результат —
RuntimeActivatedButPersistentDrift. Дополнительных restart/cleanup/rollback нет.

Это последовательное моментное доказательство, не атомарная транзакция с чужими
writers и не постоянный мониторинг. Остаётся гонка после последней проверки;
скрытый privileged ABA, включая изменение/восстановление внутри неразличимого
разрешения ctime, не исключается. Совпадение SHA не компенсирует наблюдаемое
изменение identity или metadata. READY не обещает успешные последующие connections:
OpenSSH может перечитывать persistent inputs после снятия snapshot.

## Security review: границы доказательства

* Наблюдаемые foreign inputs становятся bounded reference только после trust,
  ownership и snapshot checks caller; это не желаемые policy values или ownership.
  Adapter не делает enrollment/managed block/compensation writes.
* CLI config path/options, скрытые env assignments, новые envfiles/drop-ins и
  изменённый loaded launch contract не дают verified-policy Success.
* Include graph и negative namespaces защищены exact directory snapshot; symlinks,
  неподдерживаемые пути и mount changes дают отказ, а не обход closure.
* Conditional assignments выбранных директив исключены; Include проверяется независимо от Match. Unknown/NonCompliant не повышаются до Proven.
* `-T` повторяется на RO inputs до restart; runtime proof дополнен новым READY
  процессом с ожидаемым executable. Ошибки не скрывают B или cleanup failure.
* После READY оригинал может измениться через старый FD. Runtime факт сохраняется,
  P отдельно выявляет mismatch. Автоматического rollback/reload нет.
* Доверие к установленному OS/executable/dynamic loader/libraries остаётся
  исходной предпосылкой FIC. Нет аттестации libc/libcrypto/ld.so.preload или
  противодействия произвольной скрытой подмене всей ОС привилегированным actor.
* PAM configs, account/group databases, AuthorizedKeysFile/commands, DNS,
  moduli/KEX, session helpers и последующее чтение вне snapshot влияют на login
  после READY. Это **не входит** в C выбранных configuration values и не
  доказывает успешную/безопасную аутентификацию. Неподдерживаемые до-READY
  configuration directives/dependencies v1 не пропускает.
* Private HostKey bytes не логируются и не экспортируются. Native references,
  backups и ключи живут только внутри одноразового контейнера; экспортируются
  sanitized results.

## Validation

Результаты текущего запуска и точные ограничения:
[SSH native follow-up](verified-config-openssh-native-validation.md#ssh-adapter-v1-follow-up).
Набор unit проверяет reference, closure/limits, env/profile и malformed requests;
real Debian gate проверяет фактический adapter/sshd, а не mock restart.

## Debian policy lifecycle

1. Один process-local `sshResourceMutex` сериализует apply и всю rollback/disable
   decision; отдельного SSH flock или нового journal schema нет.
2. Ubuntu 24.04/26.04 использует verified socket profile без legacy fallback.
   ALT p11 сохраняет legacy activation/compensation; общий mutex и
   shared-file Prepared gate также защищают его SSH resource.
3. Admission требует persistent `enabled` и доказанный ready runtime. Disabled,
   masked, static, enabled-runtime, failed и inactive без Job дают отказ до записи.
   Activating/auto-restart, deactivating/reloading и inactive с pending Job могут
   ожидаться только до deadline. FIC не enable/start/unmask/reset-failed SSH.
4. Перед первым restart процесс консервативно выжидает прежнее неизвестное окно
   systemd StartLimitIntervalUSec; затем учитывает свои попытки в rolling budget
   StartLimitBurst. Ожидание происходит до записи и повторяется перед активацией.
   Поддержан interval 0 (лимит отключён) либо <=30s и burst 1..1024; большие/неясные
   лимиты Unsupported. Production admission/reference имеют 60s budget.
   Unit и лимиты не меняются. Чужие privileged restart вне контрольных точек
   не сериализуются этим локальным ledger.
5. Любой Prepared для того же main SSH resource блокирует apply и disable другой
   SSH-политики. Нет автоматического восстановления Prepared. Изменение уже
   owned value/REFRESH пока явно отвергается без rollback старого состояния.
6. У уже compliant foreign configuration не появляется ownership. При отсутствии
   актуального receipt всё равно нужен verified restart. Durable save проходит
   через существующий CAS; затем adapter доказывает A/B/C, cleanup и P, а caller
   повторно сверяет installed main identity перед journal commit.
7. Ошибка после installed/unknown write не восстанавливает historical bytes:
   provenance остаётся Prepared либо journal становится недоступен до доказанного
   recovery при неопределённой durability journal. Ответ apply — failure с
   отдельным указанием saved/runtime/provenance. Даже успешный restart не скрывает
   CleanupFailed, persistent drift или journal commit failure.
8. Единственный bounded in-memory receipt связан с boot, canonical unit, полным
   launch, PID/InvocationID/executable identity+digest, input manifests/metadata и
   доказанными policy values. Повторный apply сверяет receipt, trusted executable,
   текущее process exe, inputs и admission; при совпадении restart не нужен.
   Другие включённые значения из доверенного NET.conf могут войти в receipt
   только после независимой проверки на том же опубликованном RO snapshot.
   Несоответствие или Unsupported дополнительной политики не влияет на выбранную.
   Изменение inputs/runtime/launch инвалидирует reuse. Receipt не переживает
   restart демона и не заменяет journal/ownership.

Это моментные доказательства с повторными проверками, а не непрерывный enforcement
или атомарная защита от произвольного privileged ABA. Readiness означает READY
ожидаемого процесса на проверенном snapshot; PAM login и будущие соединения после
cleanup требуют собственных гарантий. Подготовка private mount boundaries на
shared-root хосте остаётся deployment-задачей, adapter их не создаёт.

Финальный native gate Debian12/13: на каждом по 30 generic experiments,
59 adapter cases и 24 module case groups. Реальные five-policy apply/listener,
repeated no-op, post-save/journal faults, launch refusal и late runtime proof
отказы проверены через systemd PID1/sshd. Pending restart управляется test-only
ptrace barrier с наблюдением настоящего deactivating state: success, failure,
deadline. Виртуальный admission state matrix проверяет остальные переходы.
Повторяемые команды и версии: [validation](ssh-debian-verified-policy-validation.md).
Старый linked native report описывает самостоятельный adapter.

Ubuntu socket activation: [отдельное ТЗ](ubuntu-ssh-socket-activation-spec.md).
Это будущая работа, не часть Debian completion.

## Ubuntu socket policy lifecycle

Общий `Ssh::apply()` сохраняет journal/Prepared gate, CAS/durability и post-save
no-compensation contract. `prepareRuntimeProbe()` после ownership/reference/admission
проверяет/создаёт только отсутствующий stock `/run/sshd` и проверяет native endpoint
boundary до записи. Это единственная дополнительная ephemeral подготовка, без
service start и изменения administrative enablement.

Внутренний `ActivationProfile::UbuntuSshSocket` и фиксированный activation callback
доступны только canonical ssh.service на Ubuntu; публичный generic `activate()`
по-прежнему требует active notify service без socket triggers. Ubuntu callback
выполняется под тем же RO snapshot. Port changes требуют native daemon-reload и
restart существующего active socket с kernel/FD proof; остальные изменения —
refresh service либо normal local socket trigger. Snapshot/cleanup engine общий.

Active Ubuntu rollback отказывает с сохранением ownership: legacy reload не может
подтвердить восстановление listener. Offline service+socket допускают только
ownership release, с проверками до/после CAS и явным `runtime NOT activated`.
См. authoritative [матрицу, proof, ограничения и эксплуатационные эффекты](ubuntu-ssh-socket-activation-spec.md).
