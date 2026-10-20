# SSH verified activation adapter v1

## Назначение и trusted reference

`fic/src/service/ssh/SshVerifiedActivationAdapter.h` — самостоятельный production
компонент, пока **не вызываемый SSH-политиками**. Он не пишет конфигурацию,
не получает ownership и не выполняет apply/rollback/compensation.

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

Trusted reference, observed state и FIC ownership различаются. Наличие SHA или
даже успешный result не доказывает ownership. Будущее подключение должно
передавать references из SSH transaction/backend после durability и проверки
его действующего provenance/CAS; оно потребует отдельной задачи, а не нового
журнала в adapter. Существующий `DaemonMutationJournal`, managed blocks,
`SshConfigTransaction` и `SshRollback` не изменены.

Проверяются полный набор путей, canonical lowercase SHA, дубликаты/пересечения,
manifest, лимиты generic activator и identifiers/значения выбранных политик.
Неполный reference отклоняется целиком. Общие snapshot bounds и metadata
контракт остаются [прежними](verified-config-service-activator.md).

## Поддерживаемый launch profile

Только build profiles **Debian 12/13**, подтверждённые текущим `/etc/os-release`.
Ubuntu и ALT дают Unsupported до capture/mount/restart; их units не изменяются.
Подготовка private boundaries не входит в adapter. На shared publication parent
без безопасной границы generic engine продолжает отказывать.

Используются `SystemdActivation::preflight()` и существующий typed D-Bus
`readLaunchContract`, включая canonical identity, triggers, namespace/sandbox,
loaded values и unit-source fingerprints. В v1 дополнительно требуются:

* `ssh.service`, active/running, notify/main, без pending job и socket triggers;
* vendor FragmentPath `/lib/systemd/system/ssh.service` либо
  `/usr/lib/systemd/system/ssh.service`, без DropInPaths;
* exact argv `ExecStart=/usr/sbin/sshd -D $SSHD_OPTS`, без execution flags;
* exact `ExecStartPre=/usr/sbin/sshd -t`, без flags;
* пустые ExecCondition/StartPost/Stop/StopPost, Environment/PassEnvironment/
  UnsetEnvironment;
* единственный typed EnvironmentFiles entry `[/etc/default/ssh, optional=true]`.
  Файл всё равно обязан существовать и иметь явный File reference;
* stock root credentials: пустые User/Group/SupplementaryGroups;
* root-controlled sshd, разрешённый `PlatformExecutableResolver`, с заранее
  доверенным hash в `CommandHashStore`. Adapter сам hash не enroll-ит.

Профиль строже произвольной Debian-конфигурации: локальные drop-ins, дополнительные
hooks/envfiles/options и override unit не поддерживаются даже если выглядят
безопасными. ExecReload не вызывается; обычного reload/restart fallback нет.
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
Никаких других assignments, duplicate assignments, quoting, continuation, CR,
NUL или дополнительных аргументов. Даже `SSHD_OPTS=""` пока Unsupported.
Это сознательный classifier небольшого языка, не копия systemd env parser.
`-f`, `-o`, `-p` и неизвестные opts отклоняются **до restart**.

## Include closure и отрицательное множество

`SshVerifiedInputClosure` использует `parseSshConfigLine` только внутри строгого
ASCII subset. Корень — `/etc/ssh/sshd_config`. Разрешены:

* literal absolute normalized Include без symlink, traversal, quoting/escapes;
* только glob `/absolute/reference-directory/*.conf`, с wildcard лишь в basename;
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

Дополнительные trusted directories явно задаются caller. Missing Include без
выразимой защиты namespace, directory-glob, `?`, произвольные wildcard patterns,
`~`, `%`, не-ASCII paths, неоднозначный syntax и рекурсия отклоняются.
Placeholder-файлы и автоматические исправления отсутствуют.

Whitelist остальных директив v1: PermitRootLogin, PubkeyAuthentication, UsePAM,
MaxAuthTries, Port, ListenAddress, AddressFamily, HostKey, PidFile, LogLevel,
VersionAddendum, PermitTTY, PasswordAuthentication, KbdInteractiveAuthentication,
PrintMotd, X11Forwarding, AcceptEnv, Subsystem, AuthorizedKeysFile, UseDNS,
PermitEmptyPasswords, StrictModes, LoginGraceTime. Native sshd дополнительно
проверяет их значения/арность. Все неизвестные directives и **весь Match**
отклоняются, включая Match all/exec и Include внутри условной конфигурации.
Это не доказательство всех Match contexts через несколько `-T -C` probes.

Нужен explicit HostKey; каждый такой private key и companion `.pub` должен
иметь reference coverage. Неявные defaults, HostKeyAgent, HostCertificate и
прочие неописанные launch/config dependencies v1 не принимает. Secret bytes
не включаются в diagnostics/evidence.

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
| persistent (P) | Проверенные после cleanup reference bytes/manifests и trusted metadata, отдельно от runtime |
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

## Security review: границы доказательства

* Current config никогда не становится reference автоматически; никакого journal
  enrollment/managed block/compensation write нет.
* CLI config path/options, скрытые env assignments, новые envfiles/drop-ins и
  изменённый loaded launch contract не дают verified-policy Success.
* Include graph и negative namespaces защищены exact directory snapshot; symlinks,
  неподдерживаемые пути и mount changes дают отказ, а не обход closure.
* Весь Match исключён. Unknown/NonCompliant не повышаются до Proven.
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
