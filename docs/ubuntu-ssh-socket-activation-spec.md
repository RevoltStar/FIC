# Ubuntu SSH verified socket activation — native contract

## Статус

Коммит A `49ac50a` фиксирует native audit. Production integration B использует
общий verified engine и закрытый Ubuntu socket profile; аудит и production gates
разделяются. Окончательные результаты B: **51 native group PASS на каждой Ubuntu**.
Sanitized [evidence](ubuntu-ssh-socket-policy-validation.json) содержит image IDs,
версии, реальные listener/FD facts и исходы каждого сценария; secret bytes исключены.

## Измеренная база

| Profile | openssh-server | systemd | Audit |
|---|---|---|---|
| Ubuntu24.04 | `1:9.6p1-3ubuntu13.20` | `255.4-1ubuntu8.18` | 21 native cases PASS |
| Ubuntu26.04 | `1:10.2p1-2ubuntu3.8` | `259.5-0ubuntu3.4` | 21 native cases PASS |

Обе системы проверены независимо в disposable Docker с systemd PID1, private
namespaces/cgroups, network none/loopback; без host SSH/PAM/systemd mounts.
Kernel общий: 6.6.87.2 WSL2, не независимая VM/kernel matrix.
Fixtures: `tests/integration/ssh-ubuntu-socket-research/`; сокращённые реальные
результаты в `evidence/ubuntu{2404,2604}.json`, полные generated reports под
`build-ubuntu-socket-research/<row>/`. Runner сохраняет immutable container image ID.

## Native наблюдения

* Canonical `ssh.service`, alias объявлен как `sshd.service` в Install. Наличие
  alias symlink зависит от enablement; production использует canonical name.
* Service: notify/main, `/usr/sbin/sshd -D $SSHD_OPTS`, ExecStartPre `sshd -t`,
  `/etc/default/ssh`, KillMode=process, Restart=on-failure, RuntimeDirectory=sshd,
  RuntimeDirectoryMode=0755. В 26.04 After дополнен nss-user-lookup.target.
* Socket: `ssh.socket`, Accept=no, FreeBind=yes, BindIPv6Only=ipv6-only;
  stock defaults — отдельные 0.0.0.0:22 и [::]:22. Socket enabled/active с
  service disabled/inactive — нормальный режим. После loopback connection
  новый sshd получает **те же** listening inode, которые удерживает PID1.
* На обеих системах Socket API `Listen` имеет тип `a(ss)`. Текстовый systemctl
  show повторяет Listen для нескольких endpoints; нельзя терять их через dict
  с последним значением. Production reader использует typed D-Bus.
* Socket ExecStartPre/Post/StopPre/Post имеют legacy `a(sasbttttuii)`, не Service
  Exec*Ex. В поддерживаемом socket profile все эти arrays пусты. В 26.04 есть
  дополнительные AcceptFileDescriptors/PassFileDescriptorsToExec; это не основание
  принимать произвольную FD delivery или расширять типы listening sockets.
* Stock ELF `/usr/lib/systemd/system-generators/sshd-socket-generator` читает SSH
  server configuration и follows Includes: вложенный literal Include реально
  задаёт Port. Для default any/wildcard22 output отсутствует; для AF_INET/AF_INET6
  и custom addresses/ports создаётся `ssh.socket.d/addresses.conf` в normal output.
  Его формат: generated header, Socket section, reset ListenStream и новые entries.
* Изменение persistent Port не меняет loaded Listen или kernel sockets. После
  daemon-reload loaded Listen уже новый, а actual sockets всё ещё старые. Только
  restart socket заменяет listener inode. При enabled dependency это также
  останавливает/перезапускает старый service; действующие соединения могут пострадать.
* Single-file research RO mount (не production engine) + изменение оригинала
  через старый FD: и отдельный native generator, и PID1 daemon-reload видят
  protected Port2288, хотя persistent original уже Port2299. После cleanup loaded
  configuration остаётся2288; последующий socket start без reload слушает2288.
  Это доказательство видимости защищённого input и отдельности caches, а не
  полный A/B/C/P proof всех файлов.
* Enabled/inactive socket и bind-induced failed socket воспроизведены. Disabled
  socket + manually active service — реальный service-only режим, вне профиля.
* Без `/run/sshd` оба native `sshd -T/-t` дают255 на **обеих** версиях. Отсутствие
  runtime directory при inactive service нормально, это нельзя спрятать fixture mkdir.

## Supported profile

| Socket | Service | Допуск |
|---|---|---|
| persistently enabled, active/listening, no Job | inactive/dead, no Job | поддерживается; normal connection trigger под RO inputs |
| persistently enabled, active/running либо listening, no Job | active/running, no Job | поддерживается; verified service refresh при изменении semantics |
| enabled, уже pending lifecycle | transitional/pending/auto-restart | bounded wait, затем повторный полный admission |
| disabled/masked/unknown | любое, в том числе manually active | отказ до persistent mutation; без enable/unmask/start/reset-failed |
| enabled, inactive/failed без ожидаемого Job | любое | отказ, не ремонтировать |
| active socket | terminal failed service без recovery Job | отказ; штатное внешнее восстановление допускает последующий apply |

Native inputs: существующий bounded main/.d Include closure, EnvironmentFile,
stock HostKeys и trusted executable identities. Include/Match/negative manifest,
symlink/traversal/limits полностью переиспользовать. Никакого расширения authority
на внешние Includes или присвоения ownership доверенным foreign files.

Первый профиль — один effective Port, до16 IPv4/IPv6 literal endpoints на этом
порту, без hostname/rdomain/scoped ambiguity, с возможностью локального trigger.
Stock wildcard endpoints поддерживаются. Unsupported комбинации распознавать до
save, насколько они известны заранее; native output и actual listeners проверять
повторно под RO. Unknown дополнительные units/FD delivery/overrides не поддерживать.

Существующие безопасные service Description/CPUWeight drop-ins сохранить; для
socket ограничить безопасные administrative изменения Description. Vendor units
не редактировать. Loaded source fingerprints, typed socket fields, отсутствие
неизвестных generated/admin overrides и generator binary trust обязательны.
Higher-priority generator overrides/masks в /run, /etc, /usr/local/lib отвергать.

### Runtime directory для native probes

После положительных launch/closure/ownership checks разрешить подготовку **только**
stock `/run/sshd`, если отсутствует: root:root0755 через descriptor/no-symlink path.
Проверить, что unit действительно требует именно этот RuntimeDirectory/mode/root
credentials. Existing directory с неверными ownership/mode либо symlink — отказ,
не chmod/chown чужого объекта. Учесть daemon UMask0027 при создании собственной
директории, не меняя parent umask. Это ephemeral dependency native config tests,
не enable/start службы и не policy enrollment; после запуска ею управляет systemd.
Отсутствие `/etc/ssh/sshd_not_to_be_run` проверяется в admission checkpoints.

## Sequence и production map

1. Existing SSH mutex/journal gate/ownership, socket/service admission, bounded
   references, native compliance/plan; CAS/durable save только при необходимости.
2. Тот же generic engine публикует RO input snapshot. Небольшой **закрытый Ubuntu
   SSH socket profile/hook** допускает ровно canonical ssh.service + ssh.socket,
   normal inactive service и exact TriggeredBy. Public generic API остаётся прежним.
   Default/Debian policy не получает разрешения на socket triggers/inactive service.
3. Ubuntu-specific hook не копирует и не монтирует данные: эти гарантии, watcher,
   write-denial, namespace checks и cleanup остаются в существующем engine.
4. Под RO вычислить native selected semantics и endpoint expectation. Если listener
   должен измениться: stop старого service, native daemon-reload, проверить ограниченную grammar и точный набор endpoints
   generator output **и** typed loaded Listen, restart уже active socket.
   При неизменном listener не делать лишний reload/restart socket.
5. Получить новый штатный sshd: restart уже active service либо normal loopback
   socket trigger при inactive service. Никакого systemctl start/enable/unmask.
6. READY/executable/invocation и полный listener set: exact endpoint→inode из
   kernel tcp/tcp6, уникальность без ReusePort, PID1 ownership и inheritance тем же
   sshd, отсутствие прежних controlled listeners. Один ss/Listen/TCP probe не proof.
7. После cleanup повторить P, source/loaded/socket/runtime proofs; journal commit.
   Ошибки после effect/unknown сохраняют provenance, без blind restore.
8. Receipt включает socket/generator/inode identities; no-op не пишет,
   не reload/restart socket/service. Start limits учитываются без изменения/reset:
   максимум service/socket interval и минимум burst в одном консервативном ledger.
   Исходное неизвестное окно выжидается до save; interval0 либо <=30s/burst1..1024.

Production integration: platform mode + generator executable trust catalog; существующие
Ssh adapter/reference/receipt; narrow socket typed reader/profile/hook в generic
internal APIs; отдельная bounded Ubuntu socket lifecycle/proof реализация без
второго snapshot engine. Journal schema, M1, package scripts и public IPC не менять.

### Реализация и proof

`UbuntuSshSocketFlow` содержит только фиксированный lifecycle и наблюдение;
снимки, RO mounts, observers и cleanup остаются в `VerifiedConfigServiceActivator`.
Typed D-Bus reader закрепляет все Listen entries, UnitFileState/Job/InvocationID,
источники unit/drop-ins и generator executable identity/hash. При изменении Port
проверяются generated grammar/reset/полный набор endpoints, загруженный Listen,
уникальный kernel endpoint→inode и FD PID1. Затем каждый inode должен находиться
в FD нового MainPID; лишний TCP LISTEN в sshd отвергается. Старые controlled inode
не должны оставаться LISTEN. Перед READY и после cleanup повторно закрепляются
socket source, invocation, endpoints/inodes и executable нового sshd.

Порядок ListenStream строк не является семантикой набора: допускается native
порядок IPv4/IPv6, но не дубликаты, лишние директивы/entries либо другой header.
Foreign root-controlled input не получает ownership. Receipt привязан к boot,
конфигурации/metadata, generator identity, socket contract/kernel inode и service
identity; при сбое сбрасывается. Изменение foreign source или runtime требует
нового proof, прежний SUCCESS не используется автоматически.

### Rollback граница

Prepared gate/ownership-safe CAS сохраняются. Текущее active release выполняет
предварительный native syntax/effective proof результирующего образа и всех оставшихся
ENABLE требований; затем CAS и тот же Ubuntu socket/service/generator/listener-FD engine.
Legacy reload success не используется. Offline требует остановленных socket **и** service
до/во время/после проверки и не запускает/не включает их. Fixed-unit RefUnit предотвращает
GC выгрузку, не создавая start job. Unknown/failed/pending state отказывает.
Disable ACK и неопределённые эффекты: [актуальный release contract](ssh-verified-activation-adapter.md#verified-configuration-release).
Исторические результаты B ниже не заменяют [новую release matrix](../tests/integration/verified_config_service/openssh_native/evidence/release-lifecycle.json).

## Итоговая validation B

| Gate | Результат |
|---|---|
| Ubuntu24.04 /26.04 real policy+socket native | 51 groups PASS каждое |
| Debian12 /13 OpenSSH native | 30 generic +59 adapter +24 module groups PASS каждое |
| Generic native Debian12/13 | 201 PASS каждое |
| Generic native Ubuntu24/26 | 202 PASS каждое |
| Generic native ALT p11 | 201 PASS /1 SKIP |
| SSH provenance Debian12/13, Ubuntu24/26, ALT p11 | 55 groups PASS каждое; новая offline fault matrix включена |
| Full Debian12 configure/build/CTest | 207 PASS /4 SKIP, 211 total |
| Shell/Python syntax, git diff --check | PASS |

Native команды: `tests/integration/verified_config_service/openssh_native/run-native.sh`
с image/profile из evidence; generic `tests/integration/verified_config_service/run-native.sh`;
provenance `tests/integration/ssh-provenance/run-native.sh` (все пять rows).
Все проверки реально выполнены в Docker. Root CTest намеренно пропускает privileged
native и package research gates без соответствующего окружения. Generic native
проверен отдельно. Один ранний generic Ubuntu26 запуск отказал на namespace event;
повторный полный202 PASS, production checks не ослаблялись.

51 Ubuntu group включает пять real policies/receipt, native effective values,
IPv4/IPv6/wildcard/default22, actual kernel/PID1→sshd inheritance и исчезновение старых
inode; foreign compliant/no enrollment; recursive literal Include/unrelated Match;
ослабляющие selected conditional inputs, внешние Include, symlink, foreign Port;
CAS/admission races, saved/unknown/durability/journal faults/Prepared; unsupported
units/generator mask; active/offline rollback; actual cleanup EBUSY/persistent drift,
foreign restart/generated mutation, ptrace pending-ready/timeout/failed, foreign
listener bind failure/stale listener reconciliation; known failed socket до save,
disabled socket/manual active service и допустимые administrative drop-ins.

## Ограничения

Настоящие пять policy classes + journal + systemd/sshd на обеих Ubuntu; fresh apply,
foreign compliant, no-op, Port/IPv4/IPv6/FD inheritance, stale generator/loaded/kernel
states, bad source/launch overrides, deterministic races, saved/unknown effects,
cleanup/drift/journal failure, unresolved Prepared и rollback. Debian12/13 native
module regression, provenance matrix, generic regression, full D12 build/CTest.
Транспортные PASS исследования A не являются доказательством production B.

Root can race после последней контрольной точки или выполнить скрытый ABA; нет
обещаний линейризуемости либо постоянного enforcement. Установленная OS/loader
остаётся trusted base. Нет полного daemon/IPC/package/PAM-login/VM acceptance.
Смена SSH port/listeners может прервать доступ: проверять только через независимое
управление контейнером, не экспериментировать на host SSH.

### Primary references

Native evidence выше — основа version-specific выводов. Семантика стандартных API:
[systemd.socket255](https://www.freedesktop.org/software/systemd/man/255/systemd.socket.html),
[systemd.socket259](https://www.freedesktop.org/software/systemd/man/259/systemd.socket.html),
[systemd.generator255](https://www.freedesktop.org/software/systemd/man/255/systemd.generator.html).
Generators запускаются при reload и пишут output разного priority; сам факт
успешного daemon-reload не подтверждает inputs/эффективный listener.
