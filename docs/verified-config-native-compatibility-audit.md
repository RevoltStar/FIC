# Native compatibility audit: VerifiedConfigServiceActivator / OpenSSH

Дата: 2026-10-17. Исследован исходный commit
`7e91772c0790f958cea6fc4aab23c9b878b053c7` (`main`), включая историю
`1782cc6` → `7e91772`. Это исследование, не SSH-интеграция.

**Ни одна из пяти штатных конфигураций не проходит текущий preflight.**
Подготовка private boundaries сама по себе этого не исправит: все пять units
используют запрещённый EnvironmentFile; Ubuntu дополнительно использует socket
activation, ALT — службу без notify, Debian 12 — symlink в FragmentPath.

## 1. Среды и уровень доказательств

Все пять сред — disposable Docker-контейнеры x86_64 с настоящим systemd PID 1,
не полноценные ВМ. Они разделяют **одно ядро
`6.6.87.2-microsoft-standard-WSL2`**. Проверки специфичных distro kernels,
обычного boot физических машин, enforcing SELinux и реальных package upgrades
не проводились. Наличие CAP_SYS_ADMIN в контейнере не означает эквивалентность
его mount topology обычной установленной ОС.

| Профиль | PRETTY_NAME; ID / VERSION_ID | systemd | openssh-server package | `sshd -V` |
|---|---|---|---|---|
| Debian 12 | Debian GNU/Linux 12 (bookworm); debian / 12 | 252.39-1~deb12u2 | 1:9.2p1-2+deb12u10 | OpenSSH_9.2 |
| Debian 13 | Debian GNU/Linux 13 (trixie); debian / 13 | 257.13-1~deb13u1 | 1:10.0p1-7+deb13u4 | OpenSSH_10.0p2 Debian-7+deb13u4 |
| Ubuntu 24.04 | Ubuntu 24.04.5 LTS; ubuntu / 24.04 | 255.4-1ubuntu8.18 | 1:9.6p1-3ubuntu13.20 | OpenSSH_9.6p1 Ubuntu-3ubuntu13.20 |
| Ubuntu 26.04 | Ubuntu 26.04.1 LTS; ubuntu / 26.04 | 259.5-0ubuntu3.4 | 1:10.2p1-2ubuntu3.8 | OpenSSH_10.2p1 Ubuntu-2ubuntu3.8 |
| ALT p11 | ALT Container; altlinux / 11, BUILD_ID=ALT Container 11, ALT_BRANCH_ID=p11 | 258.9-alt1 | openssh-server-9.6p1-alt7.x86_64 | OpenSSH_9.6p1 |

Debian 13: source package сохраняет имя `10.0p1`, но его patched `version.h`
содержит `SSH_PORTABLE "p2"`; это проверено, не несоответствие выбранных исходников.

Источники пакетов: Debian `deb.debian.org/debian` bookworm/trixie main;
Ubuntu `security.ubuntu.com/ubuntu` noble-security/resolute-security;
ALT p11 apt-rpm, Vendor `ALT Linux Team`, SourceRPM
`openssh-9.6p1-alt7.src.rpm`. Полные package policy и версии сохранены в
[обезличенных результатах](verified-config-native-compatibility-audit-evidence.json).

Подготовка сред отделена от наблюдения: пакеты установлены в images до загрузки
systemd, через временный policy-rc.d, запрещающий autostart при сборке Debian/
Ubuntu image. Затем восстановлен прежний policy-rc.d и выполнена первая загрузка
контейнеров с systemd. Штатные units/config не редактировались. Контейнеры без
сети и host port publishing. Debian SSH стартовал при первой загрузке; Ubuntu
открыл socket, ALT оставил службу disabled/inactive. **Команды start/stop/restart/
reload SSH, daemon-reload и mount/umount в исследуемых средах не выполнялись.**
Диагностические binary/source artifacts размещались отдельно в `/root` и build
каталогах, не в SSH/FIC configuration.

Ранее использовавшаяся ALT-ВМ `172.17.1.107` недоступна (`No route to host`);
её нынешняя конфигурация не исследована. Astra 1.8 не предоставлена:
`NOT_TESTED`, основную матрицу не блокирует.

Обозначения:

* **runtime** — фактически прочитано у запущенного systemd/файлов данной среды;
* **source** — установлено по exact-version distro source package с патчами;
* **вывод** — архитектурное следствие этих данных, не выполненная активация;
* `SUPPORTED` относится к отдельному условию, не к готовности всего компонента;
* `NOT_TESTED` — нет доказательства; `NOT_APPLICABLE` — условие неприменимо.

## 2. Сводная совместимость

| Платформа | SSH unit | Notify | EnvironmentFile | Socket activation | Mount boundaries в контейнере | Итог |
|---|---|---|---|---|---|---|
| Debian 12 | ssh.service, alias sshd.service | notify/main, active | optional /etc/default/ssh | ssh.socket установлен, inactive | private `/`, private `/run`; проходят | `REQUIRES_ACTIVATOR_CHANGE` |
| Debian 13 | ssh.service, alias sshd.service | notify/main, active | optional /etc/default/ssh | ssh.socket установлен, inactive | private `/`, private `/run`; проходят | `REQUIRES_ACTIVATOR_CHANGE` |
| Ubuntu 24.04 | ssh.service; vendor Alias=sshd.service, alias не materialized | notify/main, inactive | optional /etc/default/ssh | ssh.socket active/listening | private `/`, private `/run`; проходят | `REQUIRES_SSH_INTEGRATION_CHANGE` |
| Ubuntu 26.04 | ssh.service, alias sshd.service | notify/main, inactive | optional /etc/default/ssh | ssh.socket active/listening | private `/`, private `/run`; проходят | `REQUIRES_SSH_INTEGRATION_CHANGE` |
| ALT p11 | sshd.service | simple/none, inactive | mandatory /etc/sysconfig/sshd | ssh/sshd.socket отсутствуют | private `/`, private `/run`; проходят | `REQUIRES_SSH_INTEGRATION_CHANGE` |

Итог выбирает наиболее существенную категорию, не исключая остальных препятствий.
Ubuntu/ALT также требуют решения EnvironmentFile на уровне активатора/его launch
модели. Ни одна строка не означает обещания, что предложенные изменения достаточны
без следующих native tests. `SUPPORTED_WITH_PREPARATION` неприменим: одними
deployment действиями при сохранении stock units все обнаруженные отказы не снять.

На обычном хосте со shared `/` без подготовленных boundaries добавится
`UnsupportedConfiguration` для SSH publication parents и/или workspace.
В настоящих ВМ эта топология здесь `NOT_TESTED`.

## 3. Точный контракт текущей реализации

Authoritative code:
[Activator](../fic/src/service/VerifiedConfigServiceActivator.cpp),
[MountSupport](../fic/src/service/VerifiedConfigMountSupport.cpp),
[Systemd](../fic/src/service/VerifiedConfigSystemd.cpp),
[LaunchContract](../fic/src/service/VerifiedConfigLaunchContract.cpp).
Описание lifecycle: [component contract](verified-config-service-activator.md).

### До первого tmpfs

| Группа | Фактическое условие и отказ |
|---|---|
| Request | Канонический `.service`; 1–16 непересекающихся абсолютных нормализованных targets, не `/`, без NUL/LF/CR, `.`/`..`; path ≤4096, depth ≤64; SHA256 lowercase 64hex; directory manifest ≤4096 без конфликтов file/directory |
| Budget | Timeout >0 и ≤5 min; maxSnapshotBytes >0 и ≤64 MiB (default 8 MiB); обход ≤8192 объектов, depth ≤64 |
| Host | root и effective CAP_SYS_ADMIN; procfs/mount namespace/statx MNT_ID; enforcing SELinux отклоняется |
| Residuals | Любой mount source `fic-vcsa.*` вызывает отказ, не adoption/автоматический umount |
| Parents | Effective mount родителя каждой цели и будущего workspace private/unbindable либо slave без shared peers; shared/shared-slave/неизвестная optional metadata запрещены; нет overlap с workspace |
| Targets | Нет mount на target и nested mount в directory; все компоненты пути открываются O_NOFOLLOW; trusted root-owned parents без group/world write |
| Content | Точный SHA/manifest, обычные файлы/каталоги; symlinks/special files/special permission bits/xattrs/ACL/security labels запрещены; корректные bytes/metadata, суммарный budget |
| Manager | PID1 systemd, activator и manager в одном mount namespace; systemctl из platform resolver с уже доверенным CommandHashStore, без enrollment |
| Unit | Загруженный canonical Id, Type=notify, NotifyAccess=main; active/running, пустой Job, MainPID >0 с проверяемыми starttime/root/mount namespace, ненулевой 32hex InvocationID |
| Sandbox | PrivateMounts/Tmp/Devices, ProtectClock/KernelTunables/KernelModules/KernelLogs/ControlGroups/Home/System/Hostname должны быть `no`; RootDirectory/Image, ReadWrite/ReadOnly/InaccessiblePaths, MountFlags, BindPaths/BindReadOnlyPaths, TemporaryFileSystem — пустые |
| Typed source | Прямой `/run/systemd/private`, SO_PEERCRED uid0/pid1; все обязательные Unit/Service properties; Exec*Ex schema `a(sasasttttuii)`; argv boundaries/flags сохраняются, mutable execution status исключён |
| Unit provenance | FragmentPath обязателен; root-controlled regular fragment/drop-ins без symlinks на всём пути; ≤64 drop-in и суммарно ≤1MiB; identity/metadata/hash; NeedDaemonReload=false, Transient=false, SourcePath пуст |
| Lifecycle inputs | Ровно один ExecStart; TriggeredBy/PIDFile пусты; FileDescriptorStoreMax/NFileDescriptorStore=0; ExitType=main, RemainAfterExit=false |
| External inputs | EnvironmentFiles, LoadCredential/Encrypted, SetCredential/Encrypted, ExtensionDirectories/Images пусты; ImportCredential, когда предоставлен manager, тоже пуст |
| Context | PAMName, NetworkNamespacePath, IPCNamespacePath, LogNamespace пусты; DynamicUser/PrivateUsers/PrivateNetwork/PrivateIPC/MountAPIVFS=false; ProtectProc=default, ProcSubset=all; stdin=null, stdout/stderr только null/journal/inherit/kmsg |
| Pinned values | Environment/PassEnvironment/UnsetEnvironment, Manager.Environment, User/Group/SupplementaryGroups, WorkingDirectory, UMask, ExecSearchPath/ExecPaths/NoExecPaths, RootHash*/RootImageOptions, runtime/state/cache/log/config directory properties и все допустимые команды закрепляются и сравниваются |

Полный список typed полей — массивы `unitProperties`, `serviceProperties`,
`commands` в LaunchContract.cpp. Допустимое начальное значение не доказывает
неизменность при последующем restart. Missing required property/schema означает
fail-closed, а не silently ignored.

Создание/locking workspace — уже state-changing шаг, отдельно `NOT_TESTED`.
Требуется root-controlled workspace mode0700. Дальнейшие требования для `Success`:
снимок идентичен эталону/метаданным, ограниченный tmpfs и published targets
подтверждены read-only/mount identity; sticky observer не обнаружил interference;
launch contract стабилен; restart принят с fail job mode; новый InvocationID,
готовая active/running notify-служба, новый подтверждённый process token;
финальный snapshot/mount/contract proof; успешный reverse cleanup только собственных
mount. Ошибка cleanup **исключает Success**, даже при readinessConfirmed=true.

READY не является проверкой SHA: доказательство основано на проверенных RO inputs,
полноте дерева, launch contract, доверенной программе и моменте её READY.
Исключены атомарность generation-check/restart, произвольный CAP_SYS_ADMIN adversary,
будущие reload, SIGKILL recovery. Poll blind spots и check/umount residual race
сохраняются; аудит их не пересматривает.

## 4. Read-only preflight: метод и результаты

Добавлен [самостоятельный probe](../tests/integration/verified_config_service/audit/README.md).
Он линкует реальные reader/validators, но **не** activate/SystemdActivation restart.
`systemctl show --all` дополняет недоступный active preflight, явно помечая
code-derived checks. Ошибки reader не прекращают проверку путей и остальных условий.

Результат каждой из 82–88 проверок на платформу, её метод и причина доступны в
[evidence JSON](verified-config-native-compatibility-audit-evidence.json).
Значения credentials/environment не публикуются. `show` выдаёт `[unprintable]`
даже для пустых credentials: это `NOT_TESTED` для текстового probe. На Debian13/
Ubuntu typed reader дополнительно подтвердил пустые credential arrays. На Debian12/
ALT их typed содержимое не проверено из-за независимого reader failure.

| Условие | Debian12 | Debian13 | Ubuntu24 | Ubuntu26 | ALT |
|---|---|---|---|---|---|
| root/CAP_SYS_ADMIN, PID1/ns диагностического процесса | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| MainPID namespace/root | SUPPORTED | SUPPORTED | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE |
| active/running, InvocationID | SUPPORTED | SUPPORTED | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED |
| notify/main | SUPPORTED | SUPPORTED | SUPPORTED (unit contract) | SUPPORTED (unit contract) | UNSUPPORTED |
| EnvironmentFiles empty | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED |
| TriggeredBy empty | SUPPORTED | SUPPORTED | UNSUPPORTED | UNSUPPORTED | SUPPORTED |
| typed reader | UNSUPPORTED: `/lib` symlink | SUPPORTED | SUPPORTED | SUPPORTED | UNSUPPORTED: GetUnit отсутствует в снимке |
| validateLaunchContract | NOT_TESTED, reader failed | UNSUPPORTED: envfile | UNSUPPORTED: trigger; envfile независимо выявлен | UNSUPPORTED: trigger; envfile независимо выявлен | NOT_TESTED, reader failed |
| Старые sandbox gates, Job/PIDFile/FD store/stdin/proc | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| Main config authority/tree/manifest | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| Candidate sshd_config.d tree | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED | UNSUPPORTED symlink; **не используется основным config** |
| Include graph authority/coverage для текущего config | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| Effective parents, нет target/nested/residual mount | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED | SUPPORTED |
| FIC daemon namespace и systemctl reference hash | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |
| Lock/tmpfs/publication/restart/READY/cleanup | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED | NOT_TESTED |

FIC не установлен/не запущен в subject images; trust store не создавался ради
положительного результата. Проверен namespace probe, не отсутствующего daemon.
Нет trusted policy etalon: manifest из наблюдаемых bytes доказывает допустимость
request shape/tree, но не соответствие политике. tmpfs/RO syscalls, observer,
перезапуск/активация и cleanup в рамках аудита не исполнялись.

### Debian 12

Runtime: ssh.service active/running, notify/main, непустой InvocationID, MainPID
в namespace/root PID1; sshd.service — alias с canonical Id=ssh.service.
`ssh.socket` установлен, disabled/inactive, TriggeredBy службы пуст. Vendor fragment
`/lib/systemd/system/ssh.service`, DropInPaths пуст, NeedDaemonReload=no.
`dpkg -V openssh-server` не выявил изменений.

**Два независимых препятствия**:

1. `EnvironmentFiles=/etc/default/ssh (ignore_errors=yes)` запрещён независимо
   от текущего содержимого/отсутствия optional file.
2. Реальный `readLaunchContract` вернул
   `open controlled path /lib/systemd/system/ssh.service: Not a directory`.
   `/lib -> usr/lib`; O_NOFOLLOW traversal намеренно запрещает такой путь.
   Это совместимость reader с vendor path, не ошибка ОС и не основание разрешить
   произвольные symlinks. Безопасное решение потребует отдельного закрепления
   цепочки разрешения и canonical FD identity либо иной доверенной схемы unit provenance.

Никакого workaround или перемещения unit не выполнялось.

### Debian 13

Runtime аналогичен Debian12, но FragmentPath уже
`/usr/lib/systemd/system/ssh.service`, typed reader прошёл, получено 65 полей.
`validateLaunchContract` отклонил `external launch input unsupported: EnvironmentFiles`.
Это конкретный воспроизводимый отказ, не предположение по тексту unit.
Socket поставляется, но не active по текущей первоначальной пакетной установке;
активировать его для опыта запрещено. Возможная администраторская socket-конфигурация
должна исследоваться отдельно и попадёт под TriggeredBy gate.

### Ubuntu 24.04 / 26.04

Runtime: `ssh.socket active/listening`, `ssh.service inactive/dead`, MainPID=0,
InvocationID пуст, TriggeredBy=ssh.socket. Typed reader прошёл, validate отклонил
activation triggers; отдельная проверка также выявила EnvironmentFiles.

FragmentPath обеих `/usr/lib/systemd/system/ssh.service`. Vendor unit заявляет
`Alias=sshd.service`; Ubuntu24 alias в текущей установке не materialized
(LoadState=not-found), Ubuntu26 alias разрешается в ssh.service. Вызывать активатор
по alias всё равно неверно: он требует canonical Id. Профили FIC сначала предлагают
ssh.service, поэтому эту проблему нельзя считать текущим profile blocker.

Package scripts предпочитают socket activation на свежей установке; существующее
администраторское отключение socket может сохраняться при upgrades. Это не
утверждение, что любой Ubuntu-хост обязан иметь такую runtime-конфигурацию.
Vendor ListenStream=`0.0.0.0:22`, `[::]:22`, Accept=no; нет nondefault generated
addresses drop-in, потому что default config оставляет те же адреса/port.
DropInPaths службы пуст, NeedDaemonReload=no, sandbox не создаёт private namespace.
Из-за inactive службы её реальный mount namespace и READY runtime — NOT_APPLICABLE/
NOT_TESTED соответственно, а не вывод по чужому MainPID.

Для поддержки нужны и внешние launch inputs, и протокол socket/service, а не
безусловное разрешение TriggeredBy или запуск inactive службы из универсального
активатора. Подключений к stock port22 для искусственного запуска не выполнялось.

### ALT p11

Реальные FIC paths: `/etc/openssh/sshd_config`, base `/etc/openssh`,
`/etc/sysconfig/sshd`, `EXTRAOPTIONS`; canonical unit `sshd.service` в
`/usr/lib/systemd/system/sshd.service`. Нельзя переносить сюда Debian `/etc/ssh`.

Runtime: Type=simple, NotifyAccess=none, disabled (preset enabled), inactive/dead,
MainPID=0; ssh.socket/sshd.socket отсутствуют. `rpm -V openssh-server` — без изменений.
Тип unit и отсутствие notify подтверждены также exact ALT SRPM, не выведены из
одного только отсутствия libsystemd в ldd.

Reader в этом снимке вернул `GetUnit: No such file or directory`: inactive service
не удерживалась manager между отдельными чтениями; это дополнительное наблюдение,
не утверждение, что ALT systemd не поддерживает нужный D-Bus API. Контракт этой
inactive службы всё равно не соответствует активатору по Type/state/envfile.

`/etc/openssh` root:root mode0751, main file trusted. Основной config **не содержит
Include**. Каталог `sshd_config.d` присутствовал в исходном cached image;
сам directory не принадлежит openssh-server. В нём symlink
`20-systemd-userdb.conf -> ../../../usr/lib/systemd/sshd_config.d/20-systemd-userdb.conf`,
принадлежащий `systemd-258.9-alt1`. Target задаёт AuthorizedKeysCommand userdbctl.
Его probe справедливо отверг для candidate directory snapshot, но штатный main
его не читает. Для текущей closure достаточно main file; нельзя приписывать этому
symlink поломку штатного SSH или удалять его ради прохождения проверки.
Если будущая конфигурация включит такой каталог, потребуется явная модель
trusted symlink/vendor Include либо refusal; простой snapshot двух путей не пройдёт.

## 5. Stock launch, EnvironmentFile и socket activation

### Команды units

Debian/Ubuntu:

```ini
EnvironmentFile=-/etc/default/ssh
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t
ExecReload=/bin/kill -HUP $MAINPID
Type=notify
```

ALT:

```ini
EnvironmentFile=/etc/sysconfig/sshd
ExecStartPre=/usr/bin/ssh-keygen -A
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $EXTRAOPTIONS
ExecReload=/bin/kill -HUP $MAINPID
```

ALT имеет default Type=simple. У всех KillMode=process; Debian/Ubuntu
Restart=on-failure, ALT Restart=always. ExecStop отсутствует. Unit PIDFile пуст:
возможный внутренний sshd pid file не следует путать с systemd PIDFile property.
Environment/PassEnvironment/UnsetEnvironment не задают дополнительных stock inputs;
их loaded values закрепляет typed reader, значения не публикуются.

SSHD_OPTS/EXTRAOPTIONS подставляются systemd как argv; это не shell expansion.
Они могут содержать `-f` другой config, `-o` overrides и `-p` другой port:
соответствующие cases в exact `sshd.c` принимают эти аргументы до окончательной
обработки config. Поэтому hash только `/etc/ssh/sshd_config` ничего не доказывает,
если manager при exec прочёл иной envfile. Опциональность `-` разрешает отсутствие
файла, но не закрепляет его отсутствие при следующем запуске. NeedDaemonReload=no
не доказывает неизменность его содержимого. Кроме того, stock ExecStartPre `sshd -t`
не получает `$SSHD_OPTS`/`$EXTRAOPTIONS`: один этот syntax check не доказывает
проверку effective config будущего ExecStart.

### Socket/config разрыв

Debian12/13 поставляют socket с фиксированным ListenStream22; наблюдаемый default —
service mode. Ubuntu24/26 дополнительно устанавливают
`/usr/lib/systemd/system-generators/sshd-socket-generator`.
Exact sources: `sshd-socket-generator.c`, функции `parse_sshd_config_options`,
`write_systemd_socket_file`. Generator читает compile-time `_PATH_SERVER_CONFIG_FILE`,
Include и Port/ListenAddress/AddressFamily через parser OpenSSH, **не** переменные
из `/etc/default/ssh`. Nondefault config создаёт generated
`ssh.socket.d/addresses.conf`, сначала сбрасывая ListenStream пустым assignment.
Для defaults drop-in удаляется/не оставляется. Это подтверждено исходниками;
generator вручную не запускался.

systemd выполняет generators при initial load/daemon-reload. Package postinst
Ubuntu26 прямо комментирует это и вызывает daemon-reload/restart socket при
установке/обновлении; **аудит эти операции не выполнял**.
Для обновления уже открытых listening FD одного перечитывания unit недостаточно:
понадобится согласованный lifecycle socket и службы (удерживаемые старые FD тоже
нужно учесть), generation/identity и proof реальных listener endpoints. Порядок
без разрыва доступа/с допустимым разрывом — отдельная архитектурная задача.

sshd умеет принимать переданные manager listening FD. READY нового sshd после
restart не означает, что старый socket перечитал Port/ListenAddress. Например,
новый snapshot задаёт Port2222, но socket продолжает держать22. Аналогично CLI `-p`
и generator могут исходить из разных входов. При таком состоянии правильное
чтение config и фактическое сетевое поведение различаются. Ослаблять TriggeredBy
gate без нового протокола нельзя.

## 6. Конфигурационное дерево и mount boundaries

Debian/Ubuntu stock main содержит `Include /etc/ssh/sshd_config.d/*.conf`;
в исследованных контейнерах glob не выбрал файлов. Реальный SshConfigAudit
подтвердил trusted sourceIdentity, дополнительный обход показал только main file.
Directory root-owned0755/main0644, tree validator не обнаружил symlink, special
bits, xattrs, ACL, labels или nested mount. ALT main без Include; candidate
userdb symlink описан выше. Не проверялась произвольная конфигурация иной машины.

**Для наблюдаемого default** main+directory покрывают текстовую closure Debian/
Ubuntu, main покрывает ALT. Это условный вывод, не универсальный whitelist.
Например, drop-in может содержать `Include /opt/company/ssh/*.conf`, а основной
файл — `Include /etc/ssh-extra.conf`. Без включения этих файлов/каталогов в request
можно прочитать непроверенные bytes при restart, несмотря на правильный hash двух
стандартных targets. Нужен ограниченный транзитивный closure с отрицательным
контролем glob matches и привязкой к effective `-f`/`-o`, включая Match Include.
Простой обход файлов или hash только существующих matches не закрывает гонку
появления нового glob match. Probe консервативен, не заменяет этот будущий протокол.

Host keys, authorized_keys, NSS/PAM и команды из конфигурации — не текстовые
Include. Их изменение не становится защищённым автоматически. Для контракта
«прочитан проверенный конфигурационный текст» не нужно включать private host keys
в report/snapshot; для более сильного обещания effective SSH access нужны
отдельные trust/runtime boundaries. Этот аудит секреты не читает.

Runtime mount observations всех пяти:

* `/` — overlay private; `/etc` и SSH directory используют этот effective mount;
* `/run` — tmpfs private; `/run/fic` отсутствует, prospective workspace использует
  ближайший существующий parent `/run`;
* parent helpers и statx MNT_ID прошли; controlled targets/nested mounts/residuals
  не обнаружены; namespaces probe/PID1 совпадают; работающие Debian sshd тоже;
* это эффект disposable Docker topology, **не** результат подготовки boundaries
  на ordinary shared-root system и не доказательство поддержки такого хоста.

### Будущее развёртывание boundaries

Для request `{main file, sshd_config.d directory}` минимальный общий parent —
`/etc/ssh` (ALT `/etc/openssh`, если будет directory target); для main-only тот же
parent. Workspace требует отдельной non-shared области, например `/run/fic`,
включающей будущий `verified-config-activator`. Более широкая private `/etc`
технически охватывает цели, но воздействует на лишнюю область и не рекомендуется
как автоматическая настройка компонента. Non-shared slave допустим с риском
incoming events; shared-slave запрещён.

Подготавливать такие directory boundaries можно до FIC; после reboot mount state
нужно создавать заново. Нужен отдельный deployment design: после underlying FS и
создания runtime dirs, до FIC/конкурентных publishers; проверить namespace PID1/
службы, peer visibility и ownership boundaries. Простое позднее bind на shared
parent уже распространяется peers **до** private remount: move_mount detached
private tree само по себе этого не устраняет. Здесь не предлагается исполнять
такой небезопасный provisioning recipe.

Directory parent boundary сохраняет same-filesystem temporary sibling + rename
AtomicFileWriter до/после активации. Mount самого файла препятствовал бы rename,
и текущий preflight его запрещает. Во время краткой публикации запись прямо в
контролируемый mountpoint намеренно невозможна/конфликтует; нужен существующий FIC
serialization, а не обещание совместимости любых внешних writes в это окно.
Замена/удаление **самого parent directory** пакетным менеджером/администратором
может получить EBUSY, topology/ordering conflict; package upgrades и directory
replacement на реальной ОС здесь NOT_TESTED. Старые native fixture tests содержат
AtomicFileWriter и sibling rename, но в рамках этого аудита они не повторялись.

Deployment boundaries не должны автоматически удаляться ordinary daemon stop.
Uninstall требует отдельного owner-safe release: дождаться отсутствия activation,
проверить identity/отсутствие вложенных и чужих mount, сохранить persistent files,
не затронуть чужую topology. Не делать lazy/force umount. Эти правила — требования
к будущему deployment компоненту, **не реализованный lifecycle**.

## 7. READY: exact distro source evidence

Получены exact source versions установленных Debian/Ubuntu пакетов через
`apt-get source --download-only openssh=<source:Version>` и распакованы с Debian
patch series. ALT exact SRPM содержит уже подготовленный `openssh-9.6p1-alt7.tar`
и spec. Package origin и hashes не заменяют доверие к исполняемому коду, но
позволяют воспроизвести анализ конкретной сборки.

| Пакет / первичный источник | SHA256 .dsc / SRPM |
|---|---|
| [Debian12 9.2p1-2+deb12u10](https://deb.debian.org/debian/pool/main/o/openssh/openssh_9.2p1-2+deb12u10.dsc) | `af8cfb3ce783604abd28183a52aa0bde8c6bc603cc35758035db48d1dac5f2e2` |
| [Debian13 10.0p1-7+deb13u4](https://deb.debian.org/debian/pool/main/o/openssh/openssh_10.0p1-7+deb13u4.dsc) | `73fed3fd77d60925ed342bcb0afd3c037e4ea0d39333107bf617aa90f859910f` |
| [Ubuntu24 9.6p1-3ubuntu13.20](https://security.ubuntu.com/ubuntu/pool/main/o/openssh/openssh_9.6p1-3ubuntu13.20.dsc) | `b07807435616bd05e9f5c71b27a32ed13cfa02df2527b463296ef2fe454ef1f0` |
| [Ubuntu26 10.2p1-2ubuntu3.8](https://security.ubuntu.com/ubuntu/pool/main/o/openssh/openssh_10.2p1-2ubuntu3.8.dsc) | `5f83862e65677da1dcb509642feb14a55da88544283949a70d46eb1e2aef2d3d` |
| [ALT p11 9.6p1-alt7 SRPM mirror](https://distrib-coffee.ipsl.jussieu.fr/pub/linux/altlinux/p11/branch/files/SRPMS/openssh-9.6p1-alt7.src.rpm) | `bc64cde8a4794e7a487eecaafa1cc5d411a042247d3d06d523f58b0628483525` |

Ссылки могут исчезать при ротации repositories; фиксированы exact filenames/hash,
не обещается постоянная доступность URL. Source archives и private keys в Git не
добавляются. Primary systemd reference для READY:
[systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
[systemd.socket](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html),
[systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
Выводы о данном активаторе проверены по коду, не перенесены из latest man на старые
systemd без native property checks.

| Платформа | Compile/source evidence | Точка READY относительно чтения config | Уровень подтверждения |
|---|---|---|---|
| Debian12 | debian/rules:83 `--with-systemd`; configure.ac:4921+ HAVE_SYSTEMD; distro `systemd-socket-activation.patch` | sshd.c:1824 load, затем parse; :2139 server_listen; :2164 sd_notify READY | source + runtime stock active notify/main |
| Debian13 | configure.ac:976–977 Linux SYSTEMD_NOTIFY/SOCKET_ACTIVATION; platform-listen.c:47+ | sshd.c:1638–1641 load/parse, :1951 listen, :1961 post_listen → port-linux.c:405 READY | source + runtime stock active notify/main |
| Ubuntu24 | configure.ac:934–935, platform.c:48+; port-linux.c:391+ | sshd.c:1930 load/parse, :2239 listen, post_listen READY | exact source; stock unit inactive, READY execution NOT_TESTED |
| Ubuntu26 | configure.ac:1003–1004, platform-listen.c post_listen; port-linux.c:405+ | sshd.c:1689 load/parse, :2011 listen, post_listen READY | exact source; stock unit inactive, READY execution NOT_TESTED |
| ALT | spec:176+ configure flags; полный поиск patched C/configure.ac не содержит SYSTEMD_NOTIFY/NOTIFY_SOCKET/sd_notify/READY=1 | штатная сборка не реализует эту notify readiness boundary | exact source; stock simple unit, runtime READY NOT_TESTED |

Debian12 использует libsystemd sd_notify; остальные три Debian/Ubuntu sources
имеют Linux notify helper, поэтому отсутствие libsystemd в ldd само по себе ничего
не доказывает. ALT исследован отдельно, не экстраполирован из Ubuntu той же версии9.6.

**Ответ о достаточности READY:** для исследованных notify Debian/Ubuntu sources
в нормальном standalone listener mode READY посылается после первоначального
чтения/разбора main+Includes и server_listen, поэтому при доверии к executable,
полноте inputs и неизменном launch contract это обоснованная граница завершения
initial config load. Не является самостоятельным свидетельством совпадения bytes
с эталоном, правильности политики, доступности извне либо успешного PAM login.
Ubuntu runtime этого утверждения здесь не испытывался.

В Debian13/Ubuntu26 config и Include buffers сериализуются в re-exec state:
`sshd.c pack_config/send_rexec_state`, `sshd-session.c recv_rexec_state` и
`parse_server_config(...,"rexec",...)` (:1049–1050 Debian13; :1042–1043 Ubuntu26).
Старые Debian12/Ubuntu24 также передают config/includes при re-exec. Поэтому
поздний per-connection/Match parse нельзя просто назвать новым независимым чтением
main file с диска. Это source evidence; логика NSS/PAM/authorized_keys/других
runtime files не включена в это доказательство и требует отдельной модели.

SIGHUP в `sighup_restart` закрывает listeners и делает exec saved argv. В новых
Linux helpers есть RELOADING=1/MONOTONIC_USEC; это отличается от нового systemd
InvocationID после restart. Stock ExecReload подтверждает завершение `kill`,
но не ожидает полную проверенную активацию нового listener. `SshRuntime::activateIfRunning`
сейчас выполняет reload + is-active (либо сообщает, что inactive службе reload
не нужен); это прежний контракт, **не** эквивалент VerifiedConfigServiceActivator.
Ни SshRuntime, ни SshConfigTransaction не изменены.

После cleanup будущий SIGHUP/restart снова читает persistent files и находится
за границей однократного доказательства. При socket activation даже READY после
прочтения правильного config не подтверждает, что inherited listener endpoints
соответствуют ему. Для этого нужно отдельное доказательство поколения socket/FD,
а не только notify. Для ALT простая смена Type=simple → notify зависла бы без
реальной поддержки протокола программой: это не безопасное deployment исправление.

## 8. Варианты следующего этапа — ничего не реализовано

Обозначение сложности: M — локальный, но security-sensitive protocol; H — новый
межкомпонентный lifecycle/доказательство. Любое решение требует собственной native
матрицы, concurrency/fault tests; «минимальное» не означает разрешение ослабить gates.

| Препятствие | Минимальное безопасное решение | Более универсальный вариант | Плюсы / минусы, сложность | Units/packaging; ownership/apply/rollback |
|---|---|---|---|---|
| EnvironmentFile | Отдельно поддержать trusted regular files: закрепить список/optional absence и байты **на время чтения manager при exec**, отказать неучтённым `-f/-o/-p`; включить parents в proof | Универсальное закрепление внешних launch inputs с доказанной manager visibility/FD semantics | Сохраняет vendor units, но mount snapshots/hash-before-after сами по себе не доказывают чтение manager: inherited FD/namespace/cache нужны в threat model. H | Возможна работа без unit edits, но пока не доказана; больше deployment boundaries. Временный снимок не должен становиться ownership конфигурации; persistent journal остаётся у policy |
| EnvironmentFile — альтернативная launch model | Явно управляемый проверенный immutable argv/env вместо внешнего envfile | Специализированная контролируемая service/launcher модель | Проще доказать источник, но меняет service identity/lifecycle; не универсальный drop-in fix. H | Требует согласованных unit/packaging changes, отдельного ownership/release и rollback. Не делать временные daemon-reload/drop-ins как скрытый side effect активатора |
| Socket activation | Для первой интеграции явно поддержать только заранее выбранный service mode и отказать sockets/FD triggers | Транзакционный coordinator socket+generator+service: точные endpoints, FD ownership/generation, новый READY и внешняя проверка listener | Первый вариант уже/проще, лишает Ubuntu default socket mode; второй сохраняет его, но риск разрыва доступа/старых listeners. H | Перевод режима — явная admin/deployment операция с owner-safe unit changes, не молчаливый policy apply. Coordinator потребует нового rollback/recovery плана; текущий journal его не обеспечивает |
| Shared publication parent/workspace | Заранее provision private directory parents и `/run/fic` с проверенным boot ordering | Отдельный deployment service для bounded owner-safe mount topology, либо иная доказанная namespace launch model | Parent rename файлов сохраняется; directory replacement/package upgrades сложнее; публикация boundary под shared сама требует защиты peer namespaces. H | Future deployment/packaging задача, не activate. Топология не принадлежит config MutationJournal автоматически; teardown по identity, не по pathname |
| Debian12 FragmentPath symlink | FD-based trusted resolution известного usr-merge пути с pin всех компонентов/manager path | Отдельная модель безопасного canonical provenance для unit sources | Сохраняет stock package, но canonicalize-before-open без pin даёт race. M | Unit edits не нужны в принципе; ограничить изменение reader, не policy ownership; отдельный тест symlink substitution/ABA |
| ALT simple / нет notify | Оставить Unsupported для штатной сборки; будущая notify-capable distro сборка с соответствующим unit | Доказанный SSH-specific readiness protocol/launcher с сигналом **от actual reader**, не от наблюдателя TCP | Первый вариант честен, но не даёт ALT integration; второй сложнее/меняет модель, порт-open не доказательство config. H | Нужны distro/packaging или launch-model changes. Нельзя заменить READY произвольным sleep/systemctl active; existing rollback не трогать до отдельного ТЗ |
| Include/CLI closure | SSH-specific bounded native parsing effective config+argv, refusal неизвестных sources/symlinks, exact directory manifests | Явный config-input protocol с FD-based closure и отрицательным контролем новых glob matches | Сохраняет модель snapshot; потребуются Match/glob/absolute Include/flags tests. H | Для stock нет обязательных unit edits; adapter должен потреблять existing policy reference, не создавать второе ownership/journal |
| ALT optional userdb symlink tree | Не включать неиспользуемый directory в request; при реальном Include отказать | Доказанная trusted symlink resolution/flattening с сохранением semantics | Main-only достаточно только наблюдаемой closure; flattening может менять относительные Includes. M/H | Не удалять systemd-owned files; ownership чужого package сохраняется; policy не присваивает эти файлы |
| FIC trust/ns deployment | Нормальная существующая trusted command enrollment/provisioning и проверка daemon namespace | Полноценный deployment validation для всех executables/units/parents | Отделяет инфраструктуру от inherent несовместимости; не делать enrollment ради зелёного probe. M | Использовать existing trust lifecycle, не самостоятельный store или policy dependency |
| AtomicFileWriter / concurrency | Parent-directory boundaries, existing FIC lock ordering и короткая activation после persistent transaction | Явная сериализация всех FIC config writers + service activation, crash/recovery contract | Files rename работает вне snapshot window; внешние writers не обязаны брать FIC lock. H | Не превращать activator в writer/rollback owner. Persistent write success отдельно от activation failure; запрещено обещать полный откат при сохранённом config |

Нельзя обойти envfile простым чтением hash дважды; socket — снятием TriggeredBy
проверки; ALT — только добавлением Type=notify; boundaries — поздним
make-private после уже распространившегося attach; usr-merge — безусловным
realpath(). Все эти shortcuts теряют доказательство, ради которого создан компонент.

### Рекомендуемая последовательность

1. Зафиксировать целевой первый контракт: already-active standalone SSH, notify,
   bounded effective argv/Include closure. Debian13 — наиболее простой baseline;
   Debian12 добавить после безопасного unit-source resolution. Не подключать
   нынешний активатор к policy apply и не выдавать reload за verified activation.
2. Спроектировать и доказать закрепление EnvironmentFile **при чтении systemd**,
   включая optional absent→present, manager namespace/FD, CLI diversion и argv
   boundaries; затем native concurrency/negative tests. Это общий блокер всех
   пяти, важнее отдельной оптимизации READY.
3. Отдельно определить deployment lifecycle private parents/workspace, проверить
   на полноценной shared-root ВМ boot ordering, peer namespaces, package upgrade,
   AtomicFileWriter, owner-safe uninstall. Не включать provisioning в activate.
4. Только после предыдущих proof реализовать узкий SSH adapter с trusted policy
   etalon, Include closure и saved/applied separation, сохранив текущие
   ownership/MutationJournal/apply/rollback boundaries.
5. Ubuntu socket coordinator и ALT notify/launch protocol — отдельные этапы.
   До их завершения явно отказать неподдерживаемым режимам; перевод service mode
   требует отдельного согласованного deployment решения, не implicit fallback.
6. Gate всей интеграции: реальные distro kernels/VM + systemd/SSH startup/restart
   под snapshot, listener proof и loss-of-access recovery. Только после этого
   можно говорить о production совместимости.

## 9. Воспроизведение, validation и ограничения

Команды наблюдения: `systemctl show --all`, `cat`, `list-unit-files ssh*`,
`list-sockets ssh*`; `uname -r`, `/proc/1/comm`, `/proc/*/ns/mnt`, mountinfo,
`findmnt -T`, actual statx через FIC helpers; `dpkg-query`, `apt-cache policy`,
`rpm -q/-V`, SHA256 source metadata. Содержимое private keys и credentials не
собиралось. Точные профильные executable/config paths — в evidence JSON.

Сборка и запуск probe выполнены во всех пяти native userspaces:

```sh
cmake -S tests/integration/verified_config_service/audit -B /build \
  -DFIC_TARGET_PLATFORM=<debian-12|debian-13|ubuntu-24.04|ubuntu-26.04|alt-p11>
cmake --build /build --target verified_config_readonly_audit -j2
/root/fic-readonly-audit
python3 tests/integration/verified_config_service/audit/collect.py SUBJECT
```

Source mounted read-only в build containers; binary передан через stdin в отдельный
`/root/fic-readonly-audit` subject. Exit0 всех probes означает законченный сбор
checks, **не успешный preflight**. Проверены Python syntax, JSON consistency/status
schema и `git diff --check`. Полный FIC build/CTest и старый privileged native gate
не запускались: production/CMake CI contract не менялся, старый gate изменяет
fixture systemd/mount state и не является проверкой stock SSH compatibility.
Автономный CMake добавлен только для явно запускаемого диагностического target.

Не проверены: VM/physical distro kernels, actual FIC daemon/trust deployment,
реальный activator restart/mount/cleanup, Ubuntu stock READY execution, ALT live
process namespace/READY, произвольные administrator Include/envfiles/drop-ins,
actual network login/PAM, package upgrade через private boundary, Astra1.8.
Полный private `processToken` (включая starttime), повторное сравнение состояния
между этапами и стабильность Job/InvocationID при restart — NOT_TESTED: probe
проверяет namespace/root и отдельный снимок свойств, не выполняет full active
preflight/restart protocol. Фактически работающий Debian notify listener не доказывает успешный restart под
снимком, поскольку такого опыта не было. Нет production изменений и интеграции
с существующими policies/SSH activation/rollback/MutationJournal.
