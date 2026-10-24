# ALT p11 SSH verified activation

## Статус

Этап A: native audit завершён, **не production policy acceptance**. После коммита
`test(ssh): establish ALT p11 native activation contract` следует implementation B.
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
  существует, но verified flow не будет использовать legacy reload.
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
Не влияющий на selected policy Match допускается; conditional selected assignment
отвергается. Дополнительный штатный Subsystem/AcceptEnv уже укладывается в существующую
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

## Минимальный план B / readiness

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
* Небольшой общий SSH listener-proof helper можно выделить из Ubuntu observation
  code; ALT не использует generator/daemon-reload/PID1 FD inheritance machinery.
* Повторить runtime/launch/listener proof после cleanup и P. Receipt включает эти
  identities и trusted inputs, без нового restart при неизменности. Existing
  shared mutex/Prepared/CAS/durability/ownership/A-B-C-P используются без fallback.
* Active rollback v1 conservatively refuses before write, retaining ownership;
  positive offline service proof permits only owned artifacts release and сообщает
  runtime NotAttempted. Legacy reload SUCCESS на ALT больше не допускается.

## Reproduce / ограничения

`bash tests/integration/ssh-alt-p11-research/run-native.sh fic-ssh-audit:alt-p11`

**28 audit cases PASS**. Root marker/PID1/root+mount namespace/loopback guards и
Docker inspect запрещают host binds/network/ports. Only sanitized report/journal
экспортируются; ключи остаются в удаляемом контейнере. Fixture reset-failed между
независимыми опытами не разрешает такого поведения production. Source preparation/
package installation отсутствуют, используются настоящие установленные ALT RPMs.
Общий WSL2 kernel6.6.87.2; не VM/kernel matrix, не PAM/login/daemon/package acceptance.
Root ABA/изменения после последней проверки не устраняются. Общая deployment boundary
private mount parents и существующее ограничение owned REFRESH сохраняются.
