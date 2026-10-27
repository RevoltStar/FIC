# ALT p11 SSH verified activation

## Статус

Этапы A (native audit) и B (production integration) завершены. Audit и production
policy acceptance проверяются раздельными runners; результаты приведены ниже.
Debian/Ubuntu contracts, M1, package lifecycle и MutationJournal schema не меняются.

## Native база и подтверждённые факты

* openssh-server/common/clients `9.6p1-alt7`, systemd `258.9-alt1`.
  Immutable image ID и полные28 observations: [sanitized evidence](../tests/integration/ssh-alt-p11-research/evidence/alt-p11.json).
  rpm verification openssh-server/common чистая; main/env/unit принадлежат openssh-server;
  `/usr/bin/ssh-keygen` — openssh-common. Source RPM `openssh-9.6p1-alt7.src.rpm`.
* `/usr/sbin/sshd`, vendor `/usr/lib/systemd/system/sshd.service` (также /lib alias).
  Canonical `sshd.service`, без aliases/socket triggers/штатных SSH socket units.
  `Type=simple`, `NotifyAccess=none`, PIDFile unit пуст, `KillMode=process`,
  `Restart=always`, StartLimitInterval10s/Burst5. MainPID foreground sshd `-D`.
* Exact ExecStart `/usr/sbin/sshd -D $EXTRAOPTIONS`; два ExecStartPre:
  `/usr/bin/ssh-keygen -A`, `/usr/sbin/sshd -t`. ExecReload `/bin/kill -HUP $MAINPID`
  существует, но verified flow не использует legacy reload.
* Required EnvironmentFile `/etc/sysconfig/sshd`, штатное `EXTRAOPTIONS=`.
  Native systemd действительно принимает `-p`, `-o`, `-f`: порт/конфигурация меняются.
  Поэтому v1 принимает только одну literal empty assignment (`=`, `=''`, `=""`),
  комментарии и whitespace; shell parser и другие options не поддерживаются.
* Штатный main `/etc/openssh/sshd_config`: активны только Subsystem sftp и AcceptEnv.
  Полный package default проходит native -t/-T/-T-C после генерации штатных ключей.
  Defaults: UsePAM=yes, PubkeyAuthentication=yes, MaxAuthTries6, Port22,
  PermitRootLogin=without-password (существующий SshRuntime уже нормализует alias).
  AuthorizedKeysFile defaults содержат ALT paths/%u. Это поздние authentication
  inputs, не доказательство успешного PAM/login, и не предмет нового snapshot.
* Default HostKey: `/etc/openssh/ssh_host_{rsa,ecdsa,ed25519}_key` + public companions.
  До первого service start ключей нет и -t/-T возвращают1; stock ExecStartPre -A
  создаёт все три пары. Native active baseline имеет все6 файлов.
* ALT binary использует libpam_userpass, libpam, libaudit, libcrypto3 и другие
  дистрибутивные libraries (evidence). RPM changelog сообщает upstream security/
  OpenSSL backports и ALT client KbdInteractive default change. Это metadata,
  не полный source-level security audit. Выбранные пять server values проверены native.
* Порты создаёт **сам sshd**: LISTEN inode находятся у MainPID, не у PID1.
  После restart меняются MainPID, InvocationID и listener inode. Одна ActiveState
  не доказывает ready: simple startup может предшествовать фактическому listen.
* RO single-file research bind + old-FD write: новый штатный sshd слушает protected2288,
  persistent original уже2299. После unmount -T показывает2299, runtime остаётся2288.
  Это видимость input, а не production A/B/C/P proof.
* Pending deactivation/restart подтверждён ptrace event-stop barrier; после detach
  штатный service восстанавливается. Некорректная config наблюдаемо даёт auto-restart.

## Конфигурационная область

Stock main не содержит Include. `/etc/openssh/sshd_config.d` сам не RPM-owned,
но `20-systemd-userdb.conf` — RPM-owned systemd symlink во внешний `/usr/lib/systemd`.
Его **не читает** stock main. Автоматический capture всей .d или всего /etc/openssh
неправилен: он отвергнет stock baseline из-за неиспользуемого symlink или захватит
не относящиеся к server init клиентские/authorized-key inputs.

V1: main + env + все штатные HostKey, и optional **существующий** root-controlled
administrator Include tree `/etc/openssh/sshd_config.local.d`. FIC не создаёт эту
директорию и не добавляет Include. Native experiment подтвердил absolute/relative
Include, *.conf и recursive literal nested file именно в этом tree. Relative base
ALT — `/etc/openssh`, не `/etc/ssh`. Empty glob требует существующего защищённого
родителя и exact manifest. Внешние/другие Includes, включая stock systemd symlink
при явном подключении стандартной .d, v1 Unsupported; silently follow запрещено.
Это ограниченный административный opt-in через штатный OpenSSH Include, **не**
утверждение, что ALT поставляет такую .d topology. Include semantics также описаны
в upstream [sshd_config(5)](https://man.openbsd.org/sshd_config#Include); точный ALT
relative base/defaults проверены установленным бинарником.

Переиспользуются bounded parser/negative set/manifest/symlink/traversal/Match checks.
Match для selected policy допускается только по общему порядку строгости
[SshPolicySemantics](ssh-verified-activation-adapter.md); global-only directives,
ослабление и unsupported criteria отклоняются. Дополнительный штатный Subsystem/AcceptEnv уже укладывается в существующую
allowlist. Неизвестные initialization inputs/commands автоматически не принимаются.

## Supported state matrix

| Enablement | Runtime | Apply |
|---|---|---|
| persistently enabled | active/running, no Job, actual sshd listener ready | verified |
| enabled | activating/auto-restart/deactivating/reloading/pending Job | bounded wait, полный повторный admission |
| enabled | inactive или terminal failed | fail до save |
| disabled/masked/unknown | любое | fail до save |

Никаких product enable/start/unmask/reset-failed. Safe administrative overrides:
Description и CPUWeight1..10000 в /etc/systemd/system/sshd.service.d/*.conf;
unknown launch overrides дают отказ. Vendor unit не изменяется.

## Production flow / readiness

* ALT-specific SshApplyContract и закрытый engine profile ровно canonical
  `sshd.service`/ALT/Type=simple. Default notify/Ubuntu contracts сохраняются.
* Те же SystemdActivation/read-only launch inputs/RO publication/observer/cleanup;
  небольшой закрытый readiness predicate внутри существующего bounded loop.
  Не добавлять sd_notify, второй engine или permanent watcher.
* Strict enabled+ready admission до CAS; exact argv/pre/env и trust sshd/ssh-keygen.
  Все три native key pairs должны уже существовать и быть безопасны; -A под RO
  является no-op, отсутствие ключа — fail до save, а не authority генерировать его.
* После штатного restart: новый InvocationID и process identity, expected executable,
  no pending Job, exact native -T endpoint set и kernel LISTEN inode у **этого** sshd,
  отсутствие старых controlled inode, нормальный local SSH identification probe.
  Один port, <=16 локально проверяемых IPv4/v6 literal endpoints; неизвестное отказ.
  Readiness доказывается совместно с protected inputs/selected semantics, не TCP отдельно.
* Общий SSH listener-proof helper выделен из Ubuntu observation
  code; ALT не использует generator/daemon-reload/PID1 FD inheritance machinery.
* Повторить runtime/launch/listener proof после cleanup и P. Receipt включает эти
  identities и trusted inputs, без нового restart при неизменности. Existing
  shared mutex/Prepared/CAS/durability/ownership/A-B-C-P используются без fallback.
* Текущее active release использует тот же verified ALT engine; отдельный offline
  release не запускает службу. Контракт и отличие от прежнего v1 refusal:
  [Verified configuration release](ssh-verified-activation-adapter.md#verified-configuration-release).

## Reproduce / ограничения

`bash tests/integration/ssh-alt-p11-research/run-native.sh fic-ssh-audit:alt-p11`

**28 audit cases PASS**. Root marker/PID1/root+mount namespace/loopback guards и
Docker inspect запрещают host binds/network/ports. Only sanitized report/journal
экспортируются; ключи остаются в удаляемом контейнере. Fixture reset-failed между
независимыми опытами не разрешает такого поведения production. Source preparation/
package installation отсутствуют, используются настоящие установленные ALT RPMs.
Общий WSL2 kernel6.6.87.2; не VM/kernel matrix, не PAM/login/daemon/package acceptance.
Root ABA/изменения после последней проверки не устраняются. Общая deployment boundary
private mount parents сохраняются. Текущий owned REFRESH описан в [adapter contract](ssh-verified-activation-adapter.md#crash-consistent-ownership-refresh).

## Policy apply и rollback

| Политика | Native проверка | Эффект |
|---|---|---|
| ssh_root_login | PermitRootLogin, включая нормализацию without-password | выбранный режим входа root |
| ssh_pubkey_auth | PubkeyAuthentication yes | разрешение public-key authentication |
| ssh_use_pam | UsePAM yes | включение PAM; успешный login отдельно не проверен |
| ssh_max_auth_tries | MaxAuthTries | выбранный лимит |
| ssh_port | Port + exact ListenAddress/kernel/FD proof | новый порт; старые controlled inode отсутствуют |

Каждая реальная policy использует общий Ssh transaction: shared mutex → unresolved
Prepared gate → service/input/publication preflight → durable Prepared → CAS save →
тот же RO activation engine → cleanup/P → journal finalize. Foreign compliant
не присваивается ownership. Fresh owned apply получает runtime proof; повторный
compliant apply с действительным receipt не вызывает restart. Receipt ограничен
памятью процесса и привязан к boot/unit/process/invocation/executables/launch,
closure/metadata/selected values и listener identities. При изменении — новое proof.

A — доказанная активация с защищёнными inputs; B — полный исходный ActivationResult
с runtime/readiness/cleanup; C — native semantics выбранных policies внутри
защищённого snapshot; P — после cleanup exact persistent bytes/metadata/manifest.
Факт CAS save и R1/R1b/R5 provenance учитываются transaction отдельно от B.
SUCCESS требует всех необходимых proofs и успешного cleanup. Недоказанный эффект
после save возвращает failure с фактом записи и сохранённым Prepared/provenance;
blind compensation и legacy fallback не добавлены. CleanupFailed не становится SUCCESS.

Active rollback теперь проверяет результирующий конфиг до CAS и активирует его
через verified ALT service flow, включая readiness/listener proof. Offline release
подтверждает inactive/dead, MainPID=0, Job=0 и отсутствие triggers; службу не запускает.
Fixed-unit RefUnit удерживает безопасно загруженную unit без start job. Unknown,
failed/pending или неподдерживаемое состояние отказывает. Disable требует durable
DISABLE → свежий registry → повторный proof → journal ACK. Подробности и актуальная
матрица: [release contract](ssh-verified-activation-adapter.md#verified-configuration-release),
[release evidence](../tests/integration/verified_config_service/openssh_native/evidence/release-lifecycle.json).

Разбор kernel mountinfo использует classic locale независимо от русского UI locale.
Native ALT daemon выявил, что ru_RU с пробелом-разделителем тысяч ломал numeric stream
extraction; синтетический locale regression и настоящий RPM/SSH/IPC gate проверяют исправление.

## Validation B

Native acceptance и регрессионная матрица фиксируются в
[production evidence](alt-p11-ssh-policy-validation.json). Воспроизведение:

```bash
bash tests/integration/verified_config_service/openssh_native/run-native.sh fic-ssh-audit:alt-p11 alt-p11
```

Runner собирает реальные пять policy classes, MutationJournal и adapter. Runtime
контейнер не монтирует source/host files; временные private boundaries создаёт только
fixture. Vendor unit не переписывается. Помимо stock/fresh/no-op и Include/Match,
проверяются unsafe launch/env/keys, состояния службы, deterministic pending/ptrace,
CAS/durability/unknown writer/journal/Prepared, protocol/listener/cleanup/drift faults,
active refusal/offline release. Generic public API по-прежнему отклоняет stock
Type=simple: исключение доступно только закрытому ALT SSH profile с обязательным
readiness callback в том же engine.

Ни module gate, ни generic gate не являются installed daemon/IPC/package/PAM-login
end-to-end. После ALT следующий этап — установленный FIC на VM всех пяти платформ,
а не новая hardening-фаза. Shared WSL2 kernel и privileged container не эквивалентны
независимому ALT kernel/VM. Root ABA, действия после последней проверки и подготовка
private publication boundaries на реальном хосте остаются deployment boundaries.


### Итоговая матрица (2026-10-24)

PASS означает выполненные assertions, включая ожидаемый отказ в negative case.
Числа групп разных runners не суммируются как число независимых policy операций.

| Gate | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| ALT audit (A, не production acceptance) | 28 | 0 | 0 |
| ALT real policy/adapter, full all phase | 64 | 0 | 0 |
| Debian 12 real OpenSSH (30 generic / 59 adapter / 24 module) | 113 | 0 | 0 |
| Debian 13 real OpenSSH (30 generic / 59 adapter / 24 module) | 113 | 0 | 0 |
| Ubuntu 24.04 socket-policy | 51 | 0 | 0 |
| Ubuntu 26.04 socket-policy | 51 | 0 | 0 |
| Generic activator ALT | 201 | 0 | 1 |
| Generic activator Debian 12 / Debian 13, каждый | 201 | 0 | 0 |
| Generic activator Ubuntu 24.04 / 26.04, каждый | 202 | 0 | 0 |
| SSH provenance/rollback, каждая из пяти платформ | 55 | 0 | 0 |
| Дополнительные real-OpenSSH provenance probes Debian 12 / 13, каждый | 3 | 0 | 0 |
| Debian 12 full configure/build + CTest | 208 | 0 | 4 |
| Final targeted descriptor/resources/SSH contracts Debian 12 | 6 | 0 | 0 |

ALT generic SKIP: stock lower-layer empty SSH Include copy-up fixture отсутствует;
это отдельная generic fixture, не пропуск ALT production Include/Port/readiness.
Четыре full-CTest SKIP: generic privileged PID1 native gate (выполнен отдельно на
всех пяти платформах), opt-in package PAM hooks (`FIC_PACKAGE_PAM_HOOKS_NATIVE` не
включён), legacy DEB и RPM admission reproductions (`FIC_LEGACY_PACKAGE_ORDER_NATIVE`
не включён). Package lifecycle/M1 не проверяется этим SSH gate.

Portable pure adapter contract CTest прошёл на всех пяти build profiles.
Shell/Python syntax, safe audit guard и `git diff --check` также прошли.
Sanitized evidence хранит immutable image IDs, report SHA-256, фактические
listener/FD identities и результаты всех64 ALT групп. Ключи/backup не экспортируются.
