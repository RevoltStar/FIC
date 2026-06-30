# FIC 2.0: диаграммы работы проекта

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
    daemon -->|применяет политики| os[Linux OS]
    daemon -->|пишет| logs["/opt/fic/log"]
    daemon -->|читает и меняет| lockstatus["/opt/fic/lockstatus"]
    deviceDaemon -->|читает и меняет| db[(devices.db)]

    udev[udev events] --> dickUdev[fic-dick udev]
    systemd[systemd service] --> dickStatic[fic-dick cpu_board_memory]
    dickUdev -->|пересылает событие| deviceDaemon
    dickStatic -->|CPU, board, memory| db

    deviceDaemon -->|permanent violation| daemon
    deviceDaemon -->|USB / PCI / block sysfs enforcement| os
    gui -->|логи текущей загрузки| daemon
```

Главная идея проекта: демон `fic` владеет изменением конфигурации политик и применением обычных системных политик к ОС. `fic-dick --daemon` владеет деревом устройств, `devices.db`, udev-событиями и исполнением решений контроля устройств. `fic-cli` и `fic-gui` являются клиентами обоих IPC API: `/run/fic/fic.sock` для общих политик и `/run/fic/fic-device.sock` для дерева устройств.

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
        policyMap["init_policyMap<br/>module -> submodule -> policy -> Policy"]
        policyOps[set / enable / disable / apply]
        logApi[boot_id / log_records]
        lockApi[lock / unlock / lockstatus]
    end

    subgraph DeviceDaemon["fic-dick --daemon"]
        deviceIpc[Unix socket server<br/>/run/fic/fic-device.sock]
        deviceApi[device_get / device_children / device_attributes]
        devicePolicy[effective policy decision]
        deviceApply[USB / PCI / block enforcement]
    end

    subgraph CoreStorage[Состояние системы]
        config["/opt/fic/config"]
        modules[DAC, SYSCTL, OSS, NET, GLOBAL]
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
    deviceIpc --> devicePolicy
    devicePolicy --> deviceApply

    policyMap --> modules
    policyOps --> config
    policyOps --> modules
    logApi --> logs
    deviceApi --> db
    devicePolicy --> db
    lockApi --> lockstatus
    devicePolicy --> lockApi

    udevMode --> deviceIpc
    staticMode --> collectors
    collectors --> db
```

## 3. Жизненный цикл демона `fic`

```mermaid
flowchart TD
    start([fic start]) --> locale[Инициализация локали]
    locale --> initMap[init_policyMap]
    initMap --> oneshot{--oneshot?}

    oneshot -->|да| applyOnce[apply all enabled policies]
    applyOnce --> exitOnce([exit])

    oneshot -->|нет| socketPath["Выбор socket path<br/>--socket или /run/fic/fic.sock"]
    socketPath --> interval["Выбор interval<br/>--interval или 1800 сек"]
    interval --> signals[Регистрация SIGTERM/SIGINT]
    signals --> createSocket[create_server_socket]
    createSocket --> mainLoop{g_stop == false}

    mainLoop --> select[select socket с timeout 1 сек]
    select --> clientReady{есть клиент?}
    clientReady -->|да| accept[accept]
    accept --> serve[serve_one_client]
    serve --> readJson[read_until_eof]
    readJson --> route[handle_request]
    route --> writeJson[write JSON response]
    writeJson --> periodic

    clientReady -->|нет| periodic{пора periodic apply?}
    periodic -->|да| reload[init_policyMap]
    reload --> applyAll[apply all enabled policies]
    applyAll --> schedule[обновить nextPeriodicApply]
    schedule --> mainLoop

    periodic -->|нет| mainLoop
    mainLoop -->|stop| cleanup[close socket и unlink]
    cleanup --> stopped([fic daemon stopped])
```

## 4. IPC-запрос от CLI или GUI

```mermaid
sequenceDiagram
    participant Client as fic-cli / fic-gui
    participant IpcClient as fic::ipc::Client
    participant Socket as /run/fic/fic.sock
    participant Daemon as fic daemon
    participant Router as handle_request

    Client->>IpcClient: request(JSON payload)
    IpcClient->>Socket: connect(AF_UNIX/SOCK_STREAM)
    IpcClient->>Socket: write payload + "\n"
    IpcClient->>Socket: shutdown(SHUT_WR)
    Socket->>Daemon: accept client fd
    Daemon->>Router: parse JSON and route command
    Router-->>Daemon: JSON response
    Daemon-->>Socket: write response + "\n"
    Socket-->>IpcClient: read_until_eof
    IpcClient-->>Client: parsed JSON
```

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

Команды дерева устройств обслуживает `fic-dick --daemon` на `/run/fic/fic-device.sock`:

```mermaid
flowchart LR
    deviceCommands[device command]
    deviceCommands --> read[device_root / device_get / device_children current or include_disconnected / device_attributes / device_events]
    deviceCommands --> mutate[device_update_control_level / device_update_ignore_hierarchy / device_reset_control / device_delete]
    deviceCommands --> udev[udev_event]
    deviceCommands --> permanent[device_check_permanent]
```

## 5. Изменение и применение политики

```mermaid
flowchart TD
    clientCommand[CLI/GUI command] --> json[JSON request]
    json --> router[handle_request]

    router --> commandType{command}

    commandType -->|set_policy_value| setFn[set policyMap module policy value]
    setFn --> getPolicy[getPolicyClass]
    getPolicy --> validate[policy.validate value]
    validate --> postprocess[policy.postprocessingValue]
    postprocess --> moduleConfig[ModuleConfigFileHandler module]
    moduleConfig --> saveValue[setValue and saveConfig]
    saveValue --> reloadAfterSet[init_policyMap]

    commandType -->|enable_policy| enableFn[enable]
    enableFn --> enableConfig[ModuleConfigFileHandler.enableParam]
    enableConfig --> reloadAfterEnable[init_policyMap]

    commandType -->|disable_policy| disableFn[disable]
    disableFn --> disableConfig[ModuleConfigFileHandler.disableParam]
    disableConfig --> reloadAfterDisable[init_policyMap]

    commandType -->|apply_all / apply_module / apply_policy| reloadBeforeApply[init_policyMap]
    reloadBeforeApply --> apply[apply]
    apply --> chooseScope{scope}
    chooseScope -->|all| allModules[iterate all modules]
    chooseScope -->|module all| oneModule[iterate module policies]
    chooseScope -->|module policy| onePolicy[getPolicyClass]
    allModules --> enabledOnly{policy.isEnable?}
    oneModule --> enabledOnly
    onePolicy --> enabledOnly
    enabledOnly -->|yes| caf[Policy.apply]
    enabledOnly -->|no| skip[skip policy]
    caf --> osChange[Изменение ОС или конфигов утилит]
    caf --> log[Logger category daemon]
```

## 6. Карта модулей и политик

```mermaid
flowchart TB
    init[init_policyMap] --> arr["vector&lt;unique_ptr&lt;Policy&gt;&gt;"]

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

    arr --> sysctl[SYSCTL]
    sysctl --> fsKernel[FSKernelProtection]
    sysctl --> globalKernel[GlobalKernelProtection]
    sysctl --> networkKernel[NetworkKernelProtection]

    arr --> oss[OSS]
    oss --> display[DisplayManager]
    oss --> desktop[DesktopEnvironment]

    arr --> net[NET]
    net --> ssh[Ssh]

    arr --> global[GLOBAL]
    global --> systemSettings[SystemSettings]

    dacSystemCommandLock --> map["policyMap<br/>module -> submodule -> policy -> object"]
    dacBlockSystemFiles --> map
    dacCustomMode --> map
    sudoEnvReset --> map
    sudoPassTries --> map
    sudoSecurePath --> map
    sudoTimeout --> map
    fsKernel --> map
    globalKernel --> map
    networkKernel --> map
    display --> map
    desktop --> map
    ssh --> map
    systemSettings --> map
```

## 7. Работа GUI

```mermaid
flowchart TD
    start[fic-gui start] --> mainWindow[MainWindow]
    mainWindow --> localization[QLocalizationManager]
    localization --> ipcLoc[localization_bundle]

    mainWindow --> policyLoad[loadPoliciesFromDaemon]
    policyLoad --> ipcPolicies[policy_list all]
    ipcPolicies --> policyPages[createPolicyPage per module]

    policyPages --> edit[Пользователь меняет value или enabled]
    edit --> validateGui[validatePolicyValue]
    validateGui --> apply[Apply button]
    apply --> setLoop{для каждой измененной политики}
    setLoop --> setIfNeeded{value configurable?}
    setIfNeeded -->|да| setValue[set_policy_value]
    setIfNeeded -->|нет| state
    setValue --> state[enable_policy или disable_policy]

    mainWindow --> deviceTree[DeviceTree]
    deviceTree --> deviceSock["/run/fic/fic-device.sock"]
    deviceSock --> devGet[device_get]
    deviceSock --> devChildren[device_children]
    deviceSock --> devAttrs[device_attributes]
    deviceSock --> devEvents[device_events]
    deviceSock --> devControl[device_update_control_level / device_update_ignore_hierarchy / device_reset_control]

    mainWindow --> attrList[DeviceAttributeList]
    attrList --> devAttrs

    mainWindow --> logViewer[LogViewer / LogService]
    logViewer --> boot[boot_id]
    logViewer --> records[log_records]
```

GUI не применяет политики к ОС напрямую. Он показывает данные, валидирует ввод на стороне интерфейса и затем отправляет изменения демону отдельными IPC-командами.

## 8. Сбор и отображение устройств

```mermaid
flowchart TD
    event{Источник запуска} -->|udev rule| udevEnv[ACTION / DEVPATH / SUBSYSTEM]
    event -->|systemd service| staticRun[fic-dick cpu_board_memory]

    udevEnv --> ficDickUdev[fic-dick udev]
    ficDickUdev --> initDb[DB.initializeDatabase]
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

```mermaid
flowchart LR
    daemon[fic daemon]
    dick[fic-dick]
    gui[fic-gui]

    config["/opt/fic/config<br/>конфиги модулей и политик"]
    lang["/opt/fic/lang<br/>локализация"]
    logs["/opt/fic/log<br/>логи по boot_id и категории"]
    lockstatus["/opt/fic/lockstatus<br/>0 или 1"]
    db["/opt/fic/db/devices.db<br/>устройства, атрибуты, события"]
    proc["/proc/sys/kernel/random/boot_id"]

    daemon --> config
    daemon --> lang
    daemon --> logs
    daemon --> lockstatus
    daemon --> db
    daemon --> proc

    dick --> db
    dick --> proc
    gui -->|только через daemon API| daemon
```
