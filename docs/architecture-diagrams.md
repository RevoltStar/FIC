# FIC: диаграммы работы проекта

Документ описывает текущую архитектуру по коду `fic`, `fic-cli`, `fic-gui` и `fic-dick`.
Диаграммы написаны в Mermaid и должны отображаться в GitHub, GitLab, Obsidian и многих IDE.

## 1. Общая архитектура

```mermaid
flowchart LR
    admin[Администратор] --> cli[fic-cli]
    admin --> gui[fic-gui]

    cli -->|policy/lock/log JSON| sock["/run/fic/fic.sock"]
    gui -->|policy/lock/log JSON| sock
    sock --> daemon[fic daemon]

    cli -->|device JSON| deviceSock["/run/fic/fic-device.sock"]
    gui -->|device JSON| deviceSock
    deviceSock --> deviceDaemon["fic-dick --daemon"]

    daemon -->|читает и меняет| config["/opt/fic/config"]
    defaults["/opt/fic/share/default-config"] -->|ensure-config, только отсутствующие| config
    daemon -->|применяет политики| os[Linux OS]
    daemon -->|пишет| logs["/opt/fic/log"]
    daemon -->|читает и меняет| lockstatus["/opt/fic/lockstatus"]
    deviceDaemon -->|читает и меняет| db[(devices.db)]
    deviceDaemon -->|компилирует desired policy| rules[99-fic-devices.rules]

    udev[udev events] --> rules
    rules -->|ALLOW / DENY| deviceEnforce[fic-dick enforce / sysfs]
    rules --> dickUdev[fic-dick udev]
    systemd[systemd service] --> dickStatic[fic-dick cpu_board_memory]
    dickUdev -->|пересылает событие| deviceDaemon
    dickStatic -->|CPU, board, memory| db

    deviceDaemon -->|permanent violation| daemon
    deviceEnforce --> os
    gui -->|логи текущей загрузки| daemon
```

Главная идея проекта: демон `fic` владеет изменением общей конфигурации политик и применением обычных системных политик к ОС. `fic-dick --daemon` владеет деревом устройств, desired policy в `devices.db`, компиляцией active udev rules, initial reconciliation и runtime udev-ingestion. Hotplug ALLOW/DENY определяется generated rules до обращения к daemon/SQLite. `fic-cli` и `fic-gui` являются клиентами административных IPC API: `/run/fic/fic.sock` для общих политик и `/run/fic/fic-device.sock` для дерева устройств. Runtime udev-события после enforcement поступают в отдельный локальный endpoint `/run/fic/fic-device-events.sock`.

Категорийные политики DC (`block_usb_storage`,
`block_printers_scanners`, `block_optical_drives`) имеют фиксированное значение
`true`. Их действие определяется только статусом политики:
`ENABLE` включает блокировку категории, `DISABLE` выключает ее.
Ручные изменения правил устройства через device API меняют желаемое состояние
дерева. Если правило делает уже подключенное устройство эффективным `blocked`,
`fic-dick` не деактивирует его немедленно и возвращает предупреждение
`deferred_block`; фактическое отключение выполняется при последующем
подключении или переподключении через обработчик udev `add/change`.

Общая IPC-логика вынесена в библиотеку `fic-common/fic-ipc`; она содержит клиентский
код Unix socket/JSON-протокола и общие helpers ответа. Клиенты и демон
используют ее как публичную границу IPC вместо прямого include из `fic/src`.

Низкоуровневые общие утилиты вынесены в `fic-common/fic-core`: обработчики
конфигурационных файлов, логирование, локализация, запуск процессов, блокировки
и проверка хэшей команд. Внутренний код использует публичные заголовки
`<fic/core/...>` напрямую.

Работа с SQLite-базой устройств вынесена в библиотеку `fic-common/fic-device-db`.
`fic-dick` использует общий слой доступа к `devices.db`; демон `fic` не обслуживает
дерево устройств и не открывает эту БД в runtime.

Базовая модель политик вынесена в `fic-common/fic-policy`: `Policy`,
`PolicyApplyResult` и типы значений `PolicyTypeValue`. Конкретные политики
модулей остаются в `fic/src/modules`; общий policy API подключается через
`<fic/policy/...>`.

Доступ к daemon API намеренно задается правами Unix-сокета. Члены системной
группы `fic` считаются полными администраторами FIC и на текущем этапе имеют
полный доступ ко всем командам API демона. Это осознанное решение: обычных
пользователей не следует добавлять в группу `fic`.

## 2. Компоненты и зоны ответственности

```mermaid
flowchart TB
    subgraph Clients[Клиенты]
        cli["fic-cli<br/>terminal UI"]
        gui["fic-gui<br/>Qt Widgets UI"]
    end

    subgraph Daemon[fic]
        ipcServer[Unix socket server]
        requestRouter[handle_request]
        policyRegistry["initPolicyRegistry<br/>module -> ModuleView + submodules -> policies"]
        policyOps[set / enable / disable / apply]
        logApi[boot_id / log_records]
        lockApi[lock / unlock / lockstatus]
    end

    subgraph DeviceDaemon["fic-dick --daemon"]
        deviceIpc[Unix socket server<br/>/run/fic/fic-device.sock]
        eventIpc[Unix datagram ingress<br/>/run/fic/fic-device-events.sock]
        reconcile[initial/full reconciliation<br/>udev/sysfs inventory]
        eventQueue[bounded event queue<br/>coalescing + overflow dirty flag]
        deviceApi[device_tree_revision / device_get / device_children / device_attributes]
        deviceCompiler[DevicePolicyCompiler]
        deviceActivator[atomic rules activation]
        devicePolicy[effective policy diagnostics / PERMANENT]
    end

    subgraph CoreStorage[Состояние системы]
        defaults["/opt/fic/share/default-config<br/>package-owned defaults"]
        config["/opt/fic/config"]
        modules[AUDIT, IDENTITY_ACCESS, DAC, DC, SYSCTL, OSS, NET, FIREWALL, GLOBAL]
        logs["/opt/fic/log/&lt;boot_id&gt;/&lt;category&gt;/*.txt"]
        db["/opt/fic/db/devices.db"]
        lockstatus["/opt/fic/lockstatus"]
    end

    subgraph Collectors[fic-dick]
        udevMode[udev mode]
        staticMode[cpu_board_memory mode]
        collectors[USB / block / PCI / UDEV / CPU / Board / Memory collectors]
    end

    cli --> ipcServer
    gui --> ipcServer
    cli --> deviceIpc
    gui --> deviceIpc
    ipcServer --> requestRouter
    requestRouter --> policyMap
    requestRouter --> policyOps
    requestRouter --> logApi
    requestRouter --> lockApi
    deviceIpc --> deviceApi
    eventIpc --> eventQueue
    reconcile --> eventQueue
    eventQueue --> devicePolicy
    deviceIpc --> devicePolicy
    deviceApi --> deviceCompiler
    deviceCompiler --> deviceActivator

    policyMap --> modules
    policyOps --> config
    policyOps --> modules
    logApi --> logs
    deviceApi --> db
    devicePolicy --> db
    deviceCompiler --> db
    lockApi --> lockstatus
    devicePolicy --> lockApi

    udevMode --> deviceIpc
    staticMode --> collectors
    collectors --> db
```

## 3. Жизненный цикл демона `fic`

```mermaid
flowchart TD
    build[CMake FIC_TARGET_PLATFORM] --> compiled[Compile-time PlatformProfile]
    start([fic start]) --> profile[Создать и проверить PlatformProfile]
    compiled --> profile
    profile --> executableRegistry[Typed executable registry]
    executableRegistry --> resolver[PlatformExecutableResolver]
    resolver --> tools[sshd / systemctl / loginctl / visudo / nft]
    profile --> sshProfile[SSH config / units]
    profile --> sudoProfile[sudoers configs]
    profile --> pamProfile[PAM roots / services / option files]
    profile --> dmProfile[SDDM / LightDM / GDM configs]
    profile --> dacProfile[DAC file and command rules]
    profile --> osRelease[Проверить /etc/os-release]
    osRelease -->|несовместим| incompatible([exit with error])
    osRelease -->|совместим| locale[Инициализация локали]
    locale --> initMap[initPolicyRegistry]
    compiled --> initMap
    initMap --> oneshot{--oneshot?}

    oneshot -->|да| applyOnce[apply all enabled policies]
    applyOnce --> exitOnce([exit])

    oneshot -->|нет| socketPath["Выбор socket path<br/>--socket или /run/fic/fic.sock"]
    socketPath --> interval["Выбор interval<br/>--interval или 1800 сек"]
    interval --> signals[Регистрация SIGTERM/SIGINT]
    signals --> createSocket[create_server_socket]
    createSocket --> startupApply[initPolicyRegistry + apply enabled non-FIREWALL policies]
    startupApply --> startupFirewall[FIREWALL full reconciliation]
    startupFirewall -->|есть ошибки| startupWarn[записать ошибку и продолжить]
    startupFirewall -->|успешно| started[fic daemon started]
    startupWarn --> started
    started --> mainLoop{g_stop == false}

    mainLoop --> poll[AdminSocketTransport poll]
    poll --> clients[accept/read/write до 32 клиентов]
    clients --> ready{готов JSON-запрос?}
    ready -->|да, не более одного за цикл| route[handle_request]
    route --> queue[поставить фреймированный ответ в bounded queue]
    queue --> periodic

    ready -->|нет| periodic{пора periodic apply?}
    periodic -->|да| reload[initPolicyRegistry]
    reload --> applyAll[apply enabled non-FIREWALL policies]
    applyAll --> firewallReconcile[FIREWALL full reconciliation]
    firewallReconcile --> schedule[обновить nextPeriodicApply]
    schedule --> mainLoop

    periodic -->|нет| mainLoop
    mainLoop -->|stop| cleanup[close socket и unlink]
    cleanup --> stopped([fic daemon stopped])
```

Профиль выбирается только во время сборки. Runtime-проверка не ищет другой
профиль, а fail-closed подтверждает, что пакет запущен на предназначенной для
него ОС. `initPolicyRegistry()` передает один и тот же immutable профиль политикам
при первой и каждой последующей инициализации. Профиль владеет интеграционными
данными systemd/login, SSH, sudo, PAM, display manager и DAC. Кандидаты команд
хранятся в едином типизированном реестре, а политики получают выбранный путь
через общий `PlatformExecutableResolver`; выбор backend конкретной графической
среды и стандартные FHS/kernel-пути остаются capability-зависимыми.

## 4. IPC-запрос от CLI или GUI

```mermaid
sequenceDiagram
    participant Client as fic-cli / fic-gui
    participant IpcClient as fic::ipc::Client
    participant Socket as /run/fic/fic.sock
    participant Daemon as fic daemon
    participant Router as handle_request

    Client->>IpcClient: request(JSON payload)
    IpcClient->>Socket: connect(AF_UNIX/SOCK_SEQPACKET)
    IpcClient->>Socket: send one JSON packet with api_version, max 64 KiB
    Socket->>Daemon: accept client fd
    Daemon->>Router: parse JSON and route command
    Router-->>Daemon: JSON response
    Daemon-->>Socket: nonblocking framed JSON with api_version, total max 1 MiB
    Socket-->>IpcClient: reassemble bounded response
    IpcClient-->>Client: parsed JSON
```

Transport не вызывает обработчик прямо из `accept`: ожидающие первый пакет и
не читающие ответ клиенты остаются в неблокирующем `poll`-контуре. Первый пакет
имеет deadline 2 секунды, запись ответа — 5 секунд, клиентский запрос целиком —
30 секунд по умолчанию. В одном цикле исполняется не более одного запроса,
поэтому мутации остаются последовательными, а periodic apply не блокируется
бездействующим соединением.

Основные команды IPC:

```mermaid
flowchart LR
    commands[command]

    commands --> status[status / shutdown / boot_id]
    commands --> listing[module_list / policy_list]
    commands --> readPolicy[policy_is_enabled / policy_is_disabled / policy_value]
    commands --> mutatePolicy[set_policy_value / enable_policy / disable_policy / reload_config]
    commands --> applyPolicy[apply_all / apply_module / apply_policy]
    commands --> logs[log_records / localization_bundle]
    commands --> tools[calc_hash / lock / unlock / lockstatus]
```

Команды дерева устройств обслуживает `fic-dick --daemon` на `/run/fic/fic-device.sock`.
Этот socket является административным request/response API для GUI/CLI и не
используется как hotplug event queue:

```mermaid
flowchart LR
    deviceCommands[device command]
    deviceCommands --> read[device_tree_revision / device_root / device_get / device_children current or include_disconnected / device_attributes / device_events]
    deviceCommands --> mutate[device_update_control_level / device_update_ignore_hierarchy / device_update_children_control / device_reset_control / device_delete]
    deviceCommands --> policyStatus[device_policy_status / desired and active revision]
    deviceCommands --> compat[udev_event root-only compatibility/testing path]
    deviceCommands --> permanent[device_check_permanent]
```

Runtime udev-события идут отдельно:

```mermaid
flowchart LR
    db[(devices.db desired policy)] --> compiler[DevicePolicyCompiler]
    compiler --> active[99-fic-devices.rules]
    udev[udev add/change] --> active
    active --> decision[direct / inherited / default decision]
    decision --> enforcer["fic-dick enforce: sysfs, no SQLite"]
    decision --> helper["fic-dick udev"]
    helper -->|bounded datagram| eventSock["/run/fic/fic-device-events.sock"]
    eventSock --> auth[SO_PASSCRED root sender check]
    auth --> queue[bounded RAM queue]
    queue --> process[common process_device_event]
    overflow[overflow / delivery failure] --> dirty[reconciliation required]
    dirty --> reconcile[full udev/sysfs reconciliation]
    reconcile --> process
```

Initial inventory больше не строится через `udevadm trigger --action=add`.
При старте `fic-dick --daemon` выполняет full reconciliation текущего
udev/sysfs состояния, затем проверяет `permanent` устройства. Udev event stream
рассматривается как notification mechanism: событие сообщает, что состояние
могло измениться, а authoritative состояние берется из фактического udev/sysfs
inventory.

`device_update_control_level`, `device_update_ignore_hierarchy`,
`device_update_children_control` и `device_reset_control` являются изменениями
желаемого состояния. После commit они синхронно компилируют candidate,
атомарно публикуют rules и выполняют udev reload. Они могут
сделать уже подключенное устройство эффективным `blocked`, но не выполняют
немедленную sysfs-деактивацию. В таком случае ответ содержит
`deferred_block=true`, `deferred_blockers[]` и текстовое `warning`.

## 5. Изменение и применение политики

```mermaid
flowchart TD
    clientCommand[CLI/GUI command] --> json[JSON request]
    json --> router[handle_request]

    router --> commandType{command}

    commandType -->|set_policy_value| setFn[set registry module policy value]
    setFn --> getPolicy[getPolicyClass]
    getPolicy --> validate[policy.validate value]
    validate --> postprocess[policy.postprocessingValue]
    postprocess --> moduleConfig[ModuleConfigFileHandler module]
    moduleConfig --> saveValue[setValue and saveConfig]
    saveValue --> reloadAfterSet[initPolicyRegistry]

    commandType -->|enable_policy| enableFn[enable]
    enableFn --> enableConfig[ModuleConfigFileHandler.enableParam]
    enableConfig --> reloadAfterEnable[initPolicyRegistry]

    commandType -->|disable_policy| disableFn[disable]
    disableFn --> disableConfig[ModuleConfigFileHandler.disableParam]
    disableConfig --> reloadAfterDisable[initPolicyRegistry]

    commandType -->|apply_all / apply_module / apply_policy| reloadBeforeApply[initPolicyRegistry]
    reloadBeforeApply --> apply[apply]
    apply --> chooseScope{scope}
    chooseScope -->|all| allModules[iterate all modules]
    chooseScope -->|module all| oneModule[iterate module policies]
    chooseScope -->|module policy| onePolicy[getPolicyClass]
    allModules --> enabledOnly{policy.isEnable?}
    oneModule --> enabledOnly
    onePolicy --> enabledOnly
    enabledOnly -->|yes| capture[Logger ScopedCapture]
    enabledOnly -->|no| skip[skip policy]
    capture --> caf[Policy.apply]
    caf --> osChange[Изменение ОС или конфигов утилит]
    osChange --> verify[Проверка persistent и обязательных runtime postconditions]
    verify --> cafResult{Все обязательные эффекты достигнуты?}
    cafResult -->|да| applied[Applied]
    cafResult -->|нет или частично| failed[Failed]
    applied --> log[Logger category daemon]
    failed --> log
    log --> diagnostic[filtered LogRecord]
    diagnostic --> result[PolicyApplyResult diagnostics]
    result --> response[IPC results per policy]
```

`ScopedCapture` действует только во время одного вызова `Policy::apply()` и
хранится в thread-local контексте `Logger`. Записи добавляются в capture после
проверки `AUDIT/log_level`, поэтому файловый журнал и diagnostics используют
одинаковую фильтрацию. Результат применения владеет копией структурированных
полей `timestamp`, `level`, `category`, `message`; состояние не сохраняется в
объекте `Policy`. Объем ограничивается на уровне одного capture и всего
IPC-ответа, а усечение обозначается `diagnostics_truncated`.

`Policy::apply()` сохраняет бинарный контракт. `true` означает, что
persistent-состояние проверено и все физически возможные и безопасные без
перезагрузки runtime-эффекты применены и подтверждены. Частичное выполнение
возвращает `false`; подробности остаются в diagnostics. Потенциально опасная
активация, например remount работающей файловой системы после изменения
`/etc/fstab`, не входит в обязательные runtime-действия.

FIREWALL дополняет, но не меняет этот lifecycle. Одиночный apply включённой
firewall Policy заменяет только её собственную nftables table. После общего
startup/periodic apply pass отдельный reconciler читает статусы всех четырёх
FIREWALL Policy, удаляет stale FIC-owned tables и восстанавливает полный
desired state. Поэтому disabled Policy, которую общий `executePolicy()` не
вызывает, всё равно удаляется из фактического FIREWALL state. Отдельного
состояния включения модуля нет: все disabled означают пустой managed state, а
не остановку reconciliation.

```mermaid
flowchart LR
    conf[FIREWALL.conf] --> desired[desired rules by policy]
    actual[nft -j list ruleset] --> batch[one nft batch]
    desired --> batch
    batch --> check[nft -c -f -]
    check --> applyNft[nft -f -]
    applyNft --> owned[fic_block_rdp / fic_block_ftp / fic_custom_rules]
    exclusive[exclusive enabled] --> foreign[foreign inet/ip/ip6 filter or route input/output base chains]
    foreign --> batch
```

FIC-owned base chains имеют `policy accept`; разрешающее правило завершает
только текущую base chain, а drop остаётся терминальным для ruleset. Exclusive
mode не удаляет чужие таблицы: только влияющая base chain очищается и
пересоздаётся с прежними family/table/name/type/hook/priority и `policy accept`.
NAT, FORWARD, bridge, netdev и остальные цепочки той же таблицы не входят в
scope. Удалённые сторонние правила не восстанавливаются после отключения
exclusive policy.

Запись конфигурационных файлов централизована в `fic-core`:

```mermaid
flowchart LR
    policy[policy or subsystem] --> options[FileHandlerOptions]
    options --> handler[FileHandler / ConfigFileHandler]
    handler --> writer[AtomicFileWriter]
    sudoGraph[SudoersConfiguration] --> writer
    sysctlGraph[SysctlConfiguration] --> writer
    writer --> metadata{metadata policy}
    metadata -->|PreserveExisting| preserve[preserve existing uid gid mode]
    metadata -->|EnforceProvided| enforce[apply configured uid gid mode]
    writer --> durable[temp file + fsync + rename + directory fsync]
```

Создание отсутствующего файла по умолчанию запрещено и проверяется самим
`AtomicFileWriter`, в том числе при сохранении после чтения. Оно включается явно
только для управляемых сценариев: `/etc/sysctl.d/zzzz-fic.conf`, записи
конфигурации display manager, `/opt/fic/db/commandhash.txt` и managed
sudoers-файла. Поэтому чтение
отсутствующего системного конфига больше не имеет побочного эффекта.

`SudoersConfiguration` использует тот же низкоуровневый writer напрямую,
поскольку работает с графом файлов, а не с одним форматом `FileHandler`.
Требуемые метаданные остаются доменным решением вызывающего компонента.

`SysctlConfiguration` также является доменным обработчиком. Он различает
runtime-состояние `/proc/sys`, boot-effective persistent-конфигурацию выбранного
platform loader и представление ручного `procps sysctl --system`. Для
поддерживаемых systemd-профилей boot-effective значение считается по
`systemd-sysctl`/`sysctl.d/*.conf`: приоритет каталогов для одинаковых имен,
глобальная лексикографическая сортировка, glob/exclusion-правила и source
location. FIC владеет только `/etc/sysctl.d/zzzz-fic.conf`; `/etc/sysctl.conf`
и чужие `sysctl.d` файлы используются для диагностики, но не переписываются.
Общий `ConfigFileHandler` для этого не используется, поскольку его однофайловая
модель не выражает подавление одноименных файлов, глобальную сортировку и
отдельный FIC-owned managed file.

Доверенные hashes системных команд обновляются только в границе пакетной
транзакции:

```mermaid
flowchart LR
    transaction[dpkg or RPM transaction] --> trigger[exact dpkg trigger or RPM affected path list]
    install[initial fic install] --> sync[fic --trust-sync-platform]
    trigger --> select[match paths to profile executable candidates]
    select -->|no matches| noop[success without package query or hash write]
    select -->|affected executable IDs| partial[fic --trust-sync-platform-affected]
    profile[compiled platform profile] --> select
    profile --> resolver[executable resolver]
    resolver --> sync
    resolver --> partial
    packageDb[local package metadata and file digests] --> verify[ownership and digest verification]
    sync --> verify
    partial --> verify
    verify -->|all available files valid| batch[calculate SHA-256 batch]
    batch --> atomic[one atomic commandhash.txt save]
    verify -->|any mismatch| reject[fail without hash changes]
    runtime[normal daemon runtime] --> checked[VerifiedProcessExecutor]
    atomic --> checked
```

Для политик `Sudo` системная конфигурация рассматривается как единый include-
граф, а не как один `/etc/sudoers`:

```mermaid
flowchart LR
    sudoPolicy[Sudo policy] --> graph[SudoersConfiguration]
    graph --> mainFile[/etc/sudoers]
    graph --> includes[include files and directories]
    graph --> effective[effective Defaults and source locations]
    effective --> preflight[whole-graph preflight]
    preflight --> strategy{remediation strategy}
    strategy -->|scalar Defaults| managed[/etc/sudoers.d/zzzz-fic]
    strategy -->|authentication bypass| origin[atomic source token replacement]
    managed --> visudo[verified visudo validation]
    origin --> visudo
    visudo --> reload[reload graph and verify postcondition]
    visudo -->|failure| rollback[rollback all written sources]
```

Клиенты не передают пути sudoers-файлов через IPC. Пути появляются только из
фиксированного `/etc/sudoers` и доверенного include-графа. Для `Defaults`
изменяется только managed-файл; политика `sudo_require_authentication` изменяет
в источнике только `NOPASSWD`, `authenticate` и `exempt_group`, не расширяя
список разрешенных команд.

Для политик `SYSCTL` поток выглядит так:

```mermaid
flowchart LR
    policy[SYSCTL policy] --> runtimePreflight[read and validate /proc/sys key]
    runtimePreflight --> loader[SysctlConfiguration]
    loader --> platform[PlatformProfile sysctl loader]
    platform --> roots[systemd sysctl.d roots]
    roots --> select[same-name priority]
    select --> order[global lexical order]
    order --> effective[boot-effective exact key including globs and exclusions]
    effective -->|matches| unchanged[no write]
    effective -->|deviation| managed[/etc/sysctl.d/zzzz-fic.conf]
    managed --> writer[AtomicFileWriter root:root 0644]
    writer --> reload[reload and verify postcondition]
    reload -->|overridden| conflict[conflict with overriding source path:line]
    conflict --> rollback[restore original managed file]
    reload -->|failure| rollback
    reload -->|success| runtimeEnsure[direct /proc/sys write when needed]
    runtimeEnsure --> runtimeVerify[read and verify runtime value]
    runtimeVerify -->|failure| failed[policy failed with partial diagnostics]
```

Сторонние sysctl-файлы используются для вычисления результата и диагностики,
но не переписываются. Если после записи managed-файла другой boot-effective
source перекрывает значение, policy apply завершается ошибкой с указанием
ожидаемого значения, фактического значения и перекрывающего `path:line`, а
managed-файл откатывается. Runtime-ключ строится только из внутреннего имени
политики, проверяется и открывается без следования по symlink. Отсутствующий
ключ и любое неподтвержденное runtime-изменение делают применение неуспешным,
даже если persistent managed-файл уже подготовлен.

SSH-политики аналогично перечитывают записанный файл, получают все эффективные
значения через проверяемый `sshd -T`, а затем отдельно аудируют полный граф
`Include` и условные `Match`-переопределения. Скалярный параметр должен иметь
единственное ожидаемое значение; `Port` дополнительно проверяет полный набор
портов и порты effective-`ListenAddress`. Неоднозначный include-граф и
ослабляющее условное значение обрабатываются fail-closed. Общий
`SshConfigSyntax` используется и редактором основного файла, и отдельным
`SshConfigAudit`; дочерний include наследует копию текущего `Match`, не изменяя
контекст содержащего файла. После проверки выполняется reload активного
`ssh.service`/`sshd.service` через проверяемый `systemctl`. Неуспешный reload
считается частичным применением и возвращает ошибку. Для `/etc/fstab`
выполняется повторный разбор записанного файла, но runtime remount намеренно
исключен как потенциально опасное действие.

PAM-политики разделяют намерение политики, provider и конкретный файл
параметров:

```mermaid
flowchart TD
    authPolicy[IDENTITY_ACCESS / PAM policy] --> profile[PAM platform profile]
    profile --> services[target services and search roots]
    services --> graph[PamConfiguration effective include graph]
    graph --> providers[PamProviderInspector capability providers]
    providers --> conflict{exactly one supported provider per service?}
    conflict -->|no| reject[fail closed without write]
    conflict -->|yes| topology[topology and config/module file checks]
    topology --> overrides[conf path and argument override checks]
    overrides --> optionFile[canonical option file]
    optionFile --> writer[AtomicFileWriter root:root 0644]
    writer --> reload[reparse file and PAM graphs]
    reload --> postcondition[provider / module / value postcondition]
```

Граф учитывает `@include`, `include` и `substack`; циклы, превышение лимитов и
неподдерживаемый синтаксис отклоняются. Capability lockout распознает
`pam_faillock`, `pam_tally2` и `pam_tally`, quality — `pam_pwquality`,
`pam_passwdqc` и `pam_cracklib`, history — `pam_pwhistory` и
`pam_unix remember=`. Первая версия применяет политики только к
`pam_faillock`, `pam_pwquality` и `pam_pwhistory`; конфликтующие или
альтернативные providers диагностируются, но не мигрируются. PAM service-файлы
не переписываются: меняется канонический provider-конфиг только после
доказательства, что он уже effective во всех существующих целевых службах.

Классы identity-модуля разделяют policy metadata и владение системной
конфигурацией:

```mermaid
flowchart TD
    base[IdentityAccessPolicy] --> pamBase[PamPolicy]
    base --> sssdBase[SssdPolicy]
    base --> krbBase[KerberosPolicy]
    base --> nssBase[NssPolicy]
    base --> composite[CompositePolicy]
    pamBase --> pamConfig[PamConfiguration / PamOptionFile]
    sssdBase --> sssdConfig[SssdConfiguration]
    sssdBase --> sssdOffline[sssd_offline_credentials_expiration]
    sssdOffline --> sssdRuntime[SssdRuntime restart / rollback]
    krbBase --> krbConfig[KerberosConfiguration]
    krbBase --> ticketLifetime[kerberos_ticket_lifetime]
    nssBase --> nssConfig[NssConfiguration]
    composite --> participants[ConfigurationParticipant list]
    participants --> prepared[PreparedConfigurationChange list]
    prepared --> commit[persistent commit all]
    commit --> verifyPersistent[verify persistent all]
    verifyPersistent --> activate[runtime activation]
    activate --> verifyEffective[verify effective all]
    commit -->|failure| rollback[reverse rollback and verification]
    verifyPersistent -->|failure| rollback
    activate -->|failure| rollback
    verifyEffective -->|failure| rollback
```

Вложенные `Policy` в composite не используются: только внешний объект в
`PolicyRegistry` через вложенные `PolicyModule::submodules` владеет объектами
`Policy`, их `moduleConf`, `policyName` и значением. Composite владеет
подсистемными `ConfigurationParticipant`, и все они готовят изменения до
первой записи. Координатор является компенсирующей транзакцией, но не заявляет
crash-atomicity нескольких файлов без transaction journal.

## 6. Карта модулей и политик

```mermaid
flowchart TB
    init[initPolicyRegistry] --> arr["vector&lt;unique_ptr&lt;Policy&gt;&gt;"]

    arr --> dac[DAC]
    dac --> dacMode[ModeAndOwner]
    dacMode --> dacSystemCommandLock[systemcommandlock]
    dacMode --> dacBlockSystemFiles[blocking_user_access_to_system_files]
    dacMode --> dacCustomMode[custom_mode_and_owner]
    dac --> sudo[Sudo]
    sudo --> sudoEnvReset[sudo_env_reset]
    sudo --> sudoPassTries[sudo_passwd_tries]
    sudo --> sudoSecurePath[sudo_securepath]
    sudo --> sudoTimeout[sudo_timeout]
    sudo --> sudoRequireAuthentication[sudo_require_authentication]

    arr --> sysctl[SYSCTL]
    sysctl --> fsKernel[FSKernelProtection]
    sysctl --> globalKernel[GlobalKernelProtection]
    sysctl --> networkKernel[NetworkKernelProtection]
    globalKernel --> sysrqDisable[kernel_sysrq_disable]

    arr --> oss[OSS]
    oss --> display[DisplayManager]
    oss --> desktop[DesktopEnvironment]
    oss --> fstab[Fstab]
    oss --> grub[Grub]
    grub --> grubTimeout[grub_timeout]
    grub --> grubCmdline[grub_cmdline_linux]
    grub --> grubRecovery[grub_disable_recovery]

    arr --> net[NET]
    net --> ssh[Ssh]
    ssh --> sshPort[ssh_port]
    ssh --> sshMaxAuthTries[ssh_max_auth_tries]
    ssh --> sshRootLogin[ssh_root_login]
    ssh --> sshPubkeyAuth[ssh_pubkey_auth]

    arr --> firewall[FIREWALL]
    firewall --> blockRdp[block_rdp]
    firewall --> blockFtp[block_ftp]
    firewall --> customRules[custom_rules]
    firewall --> exclusiveControl[exclusive_firewall_control]

    arr --> identity[IDENTITY_ACCESS]
    identity --> pam[PAM]
    identity --> sssd[SSSD editor base]
    identity --> kerberos[KERBEROS editor base]
    identity --> nss[NSS editor base]
    identity -. abstract .-> composite[COMPOSITE]
    pam --> passwordMinLength[password_min_length]
    pam --> passwordMinClasses[password_min_classes]
    pam --> passwordHistoryDepth[password_history_depth]
    pam --> passwordHistoryRoot[password_history_enforce_for_root]
    pam --> failedAttempts[failed_authentication_attempts]
    pam --> countingPeriod[failed_authentication_counting_period]
    pam --> failedRoot[failed_authentication_enforce_for_root]
    pam --> unlockTime[failed_authentication_unlock_time]
    sssd --> offlineExpiration[sssd_offline_credentials_expiration]
    kerberos --> ticketLifetimePolicy[kerberos_ticket_lifetime]

    arr --> global[GLOBAL]
    global --> systemSettings[SystemSettings]
    systemSettings --> lang[lang]

    arr --> audit[AUDIT view=audit]
    audit --> auditLogging[logging]
    auditLogging --> logLevel[log_level]

    arr --> dc[DC view=device]
    dc --> dcRules[DeviceControl]

    dacSystemCommandLock --> map["PolicyRegistry<br/>module -> view + submodule -> policy -> object"]
    dacBlockSystemFiles --> map
    dacCustomMode --> map
    sudoEnvReset --> map
    sudoPassTries --> map
    sudoSecurePath --> map
    sudoTimeout --> map
    sudoRequireAuthentication --> map
    fsKernel --> map
    globalKernel --> map
    networkKernel --> map
    display --> map
    desktop --> map
    fstab --> fstabTmp[fstab_tmp_profile]
    fstab --> fstabVarTmp[fstab_var_tmp_profile]
    fstab --> fstabDevShm[fstab_dev_shm_profile]
    fstab --> fstabHome[fstab_home_profile]
    fstab --> fstabMedia[fstab_removable_media_profile]
    fstab --> fstabVarLog[fstab_var_log_secure_options]
    fstab --> fstabAudit[fstab_var_log_audit_secure_options]
    fstab --> fstabBoot[fstab_boot_profile]
    fstab --> fstabBootEfi[fstab_boot_efi_profile]
    fstab --> fstabSrv[fstab_srv_profile]
    fstab --> fstabOpt[fstab_opt_profile]
    fstabTmp --> map
    fstabVarTmp --> map
    fstabDevShm --> map
    fstabHome --> map
    fstabMedia --> map
    fstabVarLog --> map
    fstabAudit --> map
    fstabBoot --> map
    fstabBootEfi --> map
    fstabSrv --> map
    fstabOpt --> map
    sshPort --> map
    sshMaxAuthTries --> map
    sshRootLogin --> map
    sshPubkeyAuth --> map
    passwordMinLength --> map
    passwordMinClasses --> map
    passwordHistoryDepth --> map
    failedAttempts --> map
    unlockTime --> map
    lang --> map
    logLevel --> map
    dcRules --> map
```

`ModeAndOwner` выполняет `fstat`, `fchown`, `fchmod` и контрольный `fstat` через
один descriptor. После успешного `fchown` состояние перечитывается до решения о
необходимости `fchmod`, поскольку Linux может сбросить SUID/SGID при смене
владельца. Проверка режима учитывает маску `07777`, включая SUID, SGID и sticky
bit.

Обычный конечный объект открывается с `O_NOFOLLOW`. Platform profile может
задать для конкретного `FileAccessRule` точный список допустимых целей symlink в
самом policy path. Пустой список запрещает такой symlink; пользовательский
`custom_mode_and_owner` всегда использует пустой список. Относительная цель
разрешается от каталога policy path и лексически нормализуется. Сам symlink
закрепляется `O_PATH|O_NOFOLLOW`-дескриптором и читается через
`readlinkat(descriptor, "")`. Разрешённая абсолютная цель открывается от
дескриптора `/` через `openat2` с `RESOLVE_IN_ROOT`, `RESOLVE_NO_SYMLINKS` и
`RESOLVE_NO_MAGICLINKS`: промежуточные symlink в target namespace запрещены, а
все изменения относятся к одному открытому target inode. На ядре без
`openat2` profile-исключение отклоняется (fail closed), обычные пути продолжают
работать.

До возврата target descriptor имя policy symlink повторно сверяется по
`st_dev/st_ino`. Привилегированный конкурент всё ещё может переименовать его
после этой проверки; это может сделать namespace несоответствующим уже
применённому правилу, но не перенаправляет `fchown`/`fchmod` на иной inode:
операции остаются привязаны к предварительно проверенной allowlisted цели.
Отсутствующие файлы из platform profile пропускаются, поскольку соответствующий
пакет может быть не установлен; отсутствующий явно заданный
`custom_mode_and_owner` path является ошибкой. Неожиданная цель symlink и ошибки
открытия не считаются отсутствующим файлом.

В профилях Debian 12/13 и Ubuntu 24.04/26.04 для `/etc/resolv.conf` разрешены
три динамические цели `systemd-resolved`:
`/run/systemd/resolve/stub-resolv.conf`,
`/run/systemd/resolve/resolv.conf` и
`/usr/lib/systemd/resolv.conf`. Профиль ALT p11 не объявляет это исключение:
штатная для него конфигурация в проекте не предполагает управление данным
путём через эти цели. Для защищаемых системных команд исключений также нет;
пути merged-`/usr` с symlink-каталогами продолжают работать как обычные пути,
но symlink в последнем компоненте запрещён.

`ExclusivePidLock` открывает lock-файл с `O_CLOEXEC|O_NOFOLLOW`, а `FileStats`
получает close-on-exec duplicate этого descriptor. Поэтому коррекция метаданных,
`flock`, чтение/запись PID, `ftruncate` и `fsync` относятся к одному inode;
дубликат не забирает владение descriptor у lock-класса.

## 7. Работа GUI

```mermaid
flowchart TD
    start[fic-gui start] --> mainWindow[MainWindow]
    mainWindow --> localization[QLocalizationManager]
    localization --> ipcLoc[localization_bundle]

    mainWindow --> moduleService[PolicyService module_list]
    moduleService --> descriptors[ModuleDescriptor name + view]
    descriptors --> pageFactory[ModulePageFactory]
    pageFactory -->|standard| standardPage[StandardModulePage]
    pageFactory -->|device| devicePage[DeviceModulePage]
    pageFactory -->|audit| auditPage[AuditModulePage]
    pageFactory -->|unknown| protocolError[ошибка протокола]

    standardPage --> policyEditor[PolicyEditorWidget]
    devicePage --> policyEditor
    auditPage --> policyEditor
    policyEditor --> ipcPolicies[PolicyService policy_list]
    ipcPolicies --> edit[Пользователь меняет value или enabled]
    edit --> validateGui[validation by editor metadata]
    validateGui --> apply[Apply button]
    apply --> setLoop{для каждой измененной политики}
    setLoop --> setIfNeeded{value configurable?}
    setIfNeeded -->|да| setValue[set_policy_value]
    setIfNeeded -->|нет| state
    setValue --> state[enable_policy или disable_policy]

    devicePage --> deviceTree[DeviceTree]
    deviceTree --> deviceSock["/run/fic/fic-device.sock"]
    deviceSock --> devRevision[device_tree_revision every 5 seconds]
    deviceSock --> devGet[device_get]
    deviceSock --> devChildren[device_children]
    deviceSock --> devAttrs[device_attributes]
    deviceSock --> devEvents[device_events]
    deviceSock --> devControl[device_update_control_level / device_update_ignore_hierarchy / device_update_children_control / device_reset_control]

    devRevision --> changed{revision changed?}
    changed -->|no| keepTree[keep current tree]
    changed -->|yes| devChildren

    devicePage --> attrList[DeviceAttributeList]
    attrList --> devAttrs

    auditPage --> logViewer[LogViewer / LogService]
    logViewer --> boot[boot_id]
    logViewer --> records[log_records pages<br/>offset / limit до 500]
```

GUI не применяет политики к ОС напрямую. Он показывает данные, валидирует ввод на стороне интерфейса и затем отправляет изменения демону отдельными IPC-командами.
`ModuleView` хранится только в дескрипторе модуля и выбирает Qt-страницу; на
порядок или семантику применения политик он не влияет. `policy_list` не
дублирует `view`, но содержит метаданные, достаточные для стандартного
редактора. Будущий `fic-web` должен использовать тот же JSON API, не Qt-код и
не прямое чтение конфигов, device DB или лог-файлов.
Логи загружаются страницами не более 500 записей и 768 КиБ; GUI следует по
`next_offset`, пока `has_more` остается истинным. IPC-команды `boot_id` и
`log_records` не пишут audit-записи, потому что LogViewer использует их как
polling/read path; запись в тот же audit-журнал во время чтения сдвигает
offset-пагинацию и приводит к повторному отображению уже прочитанных строк.

## 8. Сбор и отображение устройств

```mermaid
flowchart TD
    event{Источник запуска} -->|udev rule| udevEnv[ACTION / DEVPATH / SUBSYSTEM]
    event -->|systemd service| staticRun[fic-dick cpu_board_memory]

    udevEnv --> generatedRules[99-fic-devices.rules]
    generatedRules --> decision[ALLOW / DENY]
    decision -->|DENY| sysfs[fic-dick enforce / sysfs]
    decision --> ficDickUdev[fic-dick udev]
    ficDickUdev --> eventSocket[device event datagram]
    eventSocket --> initDb[DB.initializeDatabase]
    initDb --> action{ACTION}

    action -->|add/change| validateUdev[check_devpath]
    validateUdev --> collectorFactory[create_collector_for_subsystem]
    collectorFactory --> usb[USBInfoCollector]
    collectorFactory --> usbmisc[UDEVInfoCollector for usbmisc]
    collectorFactory --> block[BlockInfoCollector]
    collectorFactory --> pci[PCIInfoCollector]
    collectorFactory --> generic[UDEVInfoCollector]

    usb --> createDevice[create_device_config]
    usbmisc --> createDevice
    block --> createDevice
    pci --> createDevice
    generic --> createDevice

    createDevice --> collectParams[collect udev params]
    collectParams --> hash[SHA256 hash from control params]
    hash --> parent[find or create parent device]
    parent --> upsert[update existing / convert virtual / add new]
    upsert --> writeDb[(devices.db)]

    action -->|remove| safeRemove[safe_remove_device]
    safeRemove --> writeDb

    staticRun --> cpu[CPUInfoCollector]
    staticRun --> board[BoardInfoCollector]
    staticRun --> memory[MemoryInfoCollector]
    cpu --> processDevice[InfoCollector.process_device]
    board --> processDevice
    memory --> processDevice
    processDevice --> writeDb

    writeDb --> daemonDeviceApi[fic device API]
    daemonDeviceApi --> guiTree[fic-gui DeviceTree]
```

## 9. Хранилища данных

Production-значения путей задаются один раз в
`cmake/FicInstallLayout.cmake`. На этапе конфигурации CMake из них создаются
типизированные C++ defaults для `fic-core`/`fic-ipc`, а также systemd,
tmpfiles, udev и XDG-шаблоны. Исполняемые компоненты инициализируют неизменяемый
контекст путей при старте; общий слой базы устройств получает `DBOptions`
явно и поэтому не знает о layout продукта.

Это не единый `FIC_ROOT`: config, state, logs, static data и runtime socket
остаются независимыми семантическими путями. Такой контракт позволяет менять
профиль установки через CMake без строковых замен в C++ или service-файлах.
Deb/RPM staging устанавливает именованные CMake-компоненты (`fic`, `fic-dick`,
`fic-cli`, `fic-session-agent`, `fic-gui`) и не копирует эти файлы повторно из
дерева исходников.

Product upgrade использует отдельный persistent state path и не выполняет
неявный repair при обычном старте. Версии IPC, конфигураций и SQLite независимы;
точные значения генерируются `fic-common/fic-version`. Package lifecycle
останавливает сервисы, последовательно продвигает атомарный журнал, сохраняет
конфиги и WAL-consistent SQLite backup, выполняет offline migration и только
после проверок запускает сервисы. Полный контракт и downgrade/remove policy
описаны в `docs/upgrade-contract.md`.

```mermaid
flowchart LR
    stop[stop active services] --> ensure[ensure missing working configs]
    ensure --> begin[upgrade journal: prepared]
    begin --> configBackup[backup and migrate configs]
    configBackup --> configPhase[journal: config_migrated]
    configPhase --> dbBackup[SQLite Backup API]
    dbBackup --> dbMigration[transactional DB migration and checks]
    dbMigration --> dbPhase[journal: database_migrated]
    dbPhase --> commit[journal: committed]
    commit --> trust[verified trust sync]
    trust --> start[start and health-check daemons]
```

```mermaid
flowchart LR
    daemon[fic daemon]
    dick[fic-dick]
    gui[fic-gui]

    config["/opt/fic/config<br/>конфиги модулей и политик"]
    defaults["/opt/fic/share/default-config<br/>неизменяемые package defaults"]
    lang["/opt/fic/lang<br/>локализация"]
    logs["/opt/fic/log<br/>логи по boot_id и категории"]
    lockstatus["/opt/fic/lockstatus<br/>0 или 1"]
    db["/opt/fic/db/devices.db<br/>desired policy, runtime inventory, события"]
    rules["/etc/udev/rules.d/99-fic-devices.rules<br/>active compiled policy"]
    proc["/proc/sys/kernel/random/boot_id"]

    daemon --> config
    defaults -->|ensure-config| config
    daemon --> lang
    daemon --> logs
    daemon --> lockstatus
    daemon --> proc

    dick --> db
    dick --> rules
    dick --> proc
    gui -->|только через daemon API| daemon
```

Production IPC использует профиль `ProductionAdmin`: реальный (не symlink)
runtime-каталог `root:root 0755` и сокет `root:fic 0660`. Группа `fic` может
подключаться к сокету, но не может удалить или подменить его имя в runtime-
каталоге. Явный `--socket` включает
профиль разработки с сокетом `0600`; этот режим не ослабляет production path.
Установленное дерево `/opt/fic` отделено от этой модели: оно принадлежит
`root:fic`, но группа имеет только read/traverse/execute (`2750` для каталогов,
`0640` для обычных файлов и `0750` для `/opt/fic/bin`). Член группы может
читать конфигурацию и БД для диагностики, но клиентские изменения по-прежнему
выполняются только через daemon API.
