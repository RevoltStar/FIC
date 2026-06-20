# FIC 2.0: диаграммы работы проекта

Документ описывает текущую архитектуру по коду `fic`, `fic-cli`, `fic-gui` и `fic-dick`.
Диаграммы написаны в Mermaid и должны отображаться в GitHub, GitLab, Obsidian и многих IDE.

## 1. Общая архитектура

```mermaid
flowchart LR
    admin[Администратор] --> cli[fic-cli]
    admin --> gui[fic-gui]

    cli -->|JSON over AF_UNIX| sock["/run/fic/fic.sock"]
    gui -->|JSON over AF_UNIX| sock
    sock --> daemon[fic daemon]

    daemon -->|читает и меняет| config["/opt/fic/config"]
    daemon -->|применяет политики| os[Linux OS]
    daemon -->|пишет| logs["/opt/fic/log"]
    daemon -->|читает и меняет| lockstatus["/opt/fic/lockstatus"]
    daemon -->|читает и меняет| db[(devices.db)]

    udev[udev events] --> dickUdev[fic-dick udev]
    systemd[systemd service] --> dickStatic[fic-dick cpu_board_memory]
    dickUdev -->|добавляет, обновляет, удаляет устройства| db
    dickStatic -->|CPU, board, memory| db

    gui -->|дерево устройств, атрибуты| daemon
    gui -->|логи текущей загрузки| daemon
```

Главная идея проекта: только демон `fic` владеет изменением конфигурации политик и применением настроек к ОС. `fic-cli` и `fic-gui` являются клиентами daemon API. `fic-dick` отдельно поддерживает базу устройств, а демон отдает эти данные GUI через тот же IPC-слой.

Общая IPC-логика вынесена в библиотеку `fic-common/fic-ipc`; она содержит клиентский
код Unix socket/JSON-протокола и общие helpers ответа. Клиенты и демон
используют ее как публичную границу IPC вместо прямого include из `fic/src`.

Работа с SQLite-базой устройств вынесена в библиотеку `fic-common/fic-device-db`.
Демон `fic` и сборщик `fic-dick` используют общий слой доступа к `devices.db`,
а не собирают реализацию БД вручную из исходников другого компонента.

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
        cafMap["init_cafMap<br/>module -> submodule -> policy -> Policy"]
        policyOps[set / enable / disable / apply]
        deviceApi[device_get / device_children / device_attributes]
        logApi[boot_id / log_records]
        lockApi[lock / unlock / lockstatus]
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
    ipcServer --> requestRouter
    requestRouter --> cafMap
    requestRouter --> policyOps
    requestRouter --> deviceApi
    requestRouter --> logApi
    requestRouter --> lockApi

    cafMap --> modules
    policyOps --> config
    policyOps --> modules
    logApi --> logs
    deviceApi --> db
    lockApi --> lockstatus

    udevMode --> collectors
    staticMode --> collectors
    collectors --> db
```

## 3. Жизненный цикл демона `fic`

```mermaid
flowchart TD
    start([fic start]) --> locale[Инициализация локали]
    locale --> initMap[init_cafMap]
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
    periodic -->|да| reload[init_cafMap]
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
    commands --> devices[device_get / device_children / device_attributes / device_update_control_level / device_delete]
    commands --> logs[log_records / localization_bundle]
    commands --> tools[calc_hash / lock / unlock / lockstatus]
```

## 5. Изменение и применение политики

```mermaid
flowchart TD
    clientCommand[CLI/GUI command] --> json[JSON request]
    json --> router[handle_request]

    router --> commandType{command}

    commandType -->|set_policy_value| setFn[set cafMap module policy value]
    setFn --> getPolicy[getPolicyClass]
    getPolicy --> validate[policy.validate value]
    validate --> postprocess[policy.postprocessingValue]
    postprocess --> moduleConfig[ModuleConfigFileHandler module]
    moduleConfig --> saveValue[setValue and saveConfig]
    saveValue --> reloadAfterSet[init_cafMap]

    commandType -->|enable_policy| enableFn[enable]
    enableFn --> enableConfig[ModuleConfigFileHandler.enableParam]
    enableConfig --> reloadAfterEnable[init_cafMap]

    commandType -->|disable_policy| disableFn[disable]
    disableFn --> disableConfig[ModuleConfigFileHandler.disableParam]
    disableConfig --> reloadAfterDisable[init_cafMap]

    commandType -->|apply_all / apply_module / apply_policy| reloadBeforeApply[init_cafMap]
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
    init[init_cafMap] --> arr["vector&lt;shared_ptr&lt;Policy&gt;&gt;"]

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

    dacSystemCommandLock --> map["cafMap<br/>module -> submodule -> policy -> object"]
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
    deviceTree --> devGet[device_get]
    deviceTree --> devChildren[device_children]
    deviceTree --> devAttrs[device_attributes]
    deviceTree --> devControl[device_update_control_level]

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

    action -->|add/change| validateUdev[check_devpath and check_excluded_subsystem]
    validateUdev --> collectorFactory[create_collector_for_subsystem]
    collectorFactory --> usb[USBInfoCollector]
    collectorFactory --> block[BlockInfoCollector]
    collectorFactory --> pci[PCIInfoCollector]
    collectorFactory --> generic[UDEVInfoCollector]

    usb --> createDevice[create_device_config]
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
