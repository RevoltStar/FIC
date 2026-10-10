# fic

`fic` - основной демон Free Integrity Control. Компонент отвечает за применение политик безопасности, периодическую проверку состояния ОС и централизованное изменение конфигурации FIC.

## Назначение

В архитектуре FIC демон является единственным компонентом, который напрямую изменяет конфигурационные файлы и применяет политики к системе. Клиентские компоненты (`fic-cli` и `fic-gui`) не пишут в `/opt/fic/config` напрямую: они отправляют команды демону через Unix-сокет.

Такой подход нужен, чтобы:

- держать права на изменение конфигурации и применение политик в одном процессе;
- исключить гонки между CLI, GUI и периодической проверкой;
- иметь единый журнал действий и единую точку валидации входных команд;
- разрешить клиентам работать без прямого доступа на запись к системным конфигам FIC.

## Основные обязанности

`fic` выполняет следующие задачи:

- загружает конфигурацию политик из `/opt/fic/config`;
- поддерживает реестр `PolicyRegistry`, где модуль явно регистрируется со своим
  `ModuleView` до регистрации policies и владеет картой подмодулей/политик;
- периодически применяет включенные политики;
- принимает IPC-команды от `fic-cli` и `fic-gui`;
- изменяет значения политик по командам `set_policy_value`;
- включает и отключает политики по командам `enable_policy` и `disable_policy`;
- немедленно применяет все политики, модуль или отдельную политику;
- выполняет вспомогательные действия: расчет hash для команд, lock/unlock/status.

`PolicyRegistry` инициализируется fail-closed: production registry сначала
полностью строится во временном объекте и только затем заменяет текущее
состояние. Ошибка startup initialization завершает daemon до создания socket и
до policy apply. Ошибка runtime reload сохраняет последний корректный registry;
зависимые policy apply, DC regeneration и FIREWALL reconciliation не
выполняются.

Политики DC `block_usb_storage`, `block_printers_scanners` и
`block_optical_drives` имеют фиксированное значение `true`; администратор
управляет ими только через `enable_policy`/`disable_policy`.

## Запуск

Обычный запуск демона:

```bash
fic
```

Запуск с явным интервалом периодической проверки:

```bash
fic --interval 1800
```

Запуск с нестандартным путем к Unix-сокету:

```bash
fic --socket /tmp/fic.sock --interval 60
```

## Unix-сокет

По умолчанию демон слушает:

```text
/run/fic/fic.sock
```

Путь задан в общем IPC-заголовке:

```text
fic-common/fic-ipc/include/fic/ipc/FicIpcClient.h
```

В пакетной установке каталог `/run/fic` создается через systemd-tmpfiles:

```text
/usr/lib/tmpfiles.d/fic.conf
```

Для разработки и аварийного fallback демон также проверяет runtime-каталог при
создании сокета:

- создает runtime-каталог, если он отсутствует;
- выставляет владельца `root:root` и права `0755` на `/run/fic`, поэтому группа
  `fic` не может удалять или подменять имена сокетов;
- если существует группа `fic`, назначает ее группой socket-файла;
- выставляет права `0660` на socket-файл.

## Модель доступа

Доступ к API демона намеренно контролируется на уровне Unix socket permissions.
Пользователи из группы `fic` считаются полными администраторами FIC и на текущем
этапе имеют полный доступ ко всем командам daemon API: изменение конфигурации,
включение и отключение политик, применение политик, lock/unlock, пересчет hash
и штатная остановка демона. Дерево устройств обслуживает отдельный socket API
`fic-dick --daemon`.

Это осознанное архитектурное решение. Простых пользователей не следует добавлять
в группу `fic`.

Для тестов и разработки можно использовать отдельный сокет через `--socket`. Клиенты также поддерживают переменную окружения `FIC_SOCKET_PATH`.

## IPC-протокол

Клиент открывает одно `AF_UNIX/SOCK_SEQPACKET`-соединение на запрос и отправляет
JSON одним пакетом без завершающего перевода строки. Каждый запрос обязан
содержать целочисленное `"api_version":1`; клиент также требует ту же версию в
ответе. Несовпадающая или отсутствующая версия отклоняется до маршрутизации
команды. Размер запроса ограничен
64 КиБ. JSON-ответ размером до 1 МиБ передается последовательностью пакетов с
16-байтным заголовком `magic/total-size/offset/chunk-size` в network byte order.
Общий клиент `fic::ipc::Client` скрывает фрейминг от CLI и GUI.

Демон держит не более 32 соединений, закрывает клиента, не приславшего первый
пакет за 2 секунды, и отводит не более 5 секунд на неблокирующую запись ответа.
Клиентский deadline по умолчанию — 30 секунд.

`log_records` является постраничной командой: принимает непрозрачный `cursor`
(пустая строка начинает полную загрузку) и `limit` от 1 до 500, возвращает
`has_more` и `next_cursor`. Cursor версии 2 является фиксированным opaque token;
daemon хранит в ограниченном in-memory хранилище привязанные к token `boot_id`
и отдельные relative path, `st_dev`, `st_ino` и byte offset каждого файла.
Поэтому число файлов не увеличивает IPC request, а добавление строки в одном
файле не сдвигает позицию другого. Новый файл читается с начала; offset
продвигается только за полностью завершённые `\n` записи. Исчезновение/смена
inode, усечение ниже сохранённого offset, рестарт daemon или вытеснение token
возвращают `reload_required=true`; клиент должен очистить текущую модель и
начать полную загрузку с пустым cursor. Одна страница дополнительно ограничена
768 КиБ; отдельная строка лога перед отправкой ограничивается 16 КиБ и
помечается `line_truncated`.

Базовый успешный ответ:

```json
{"ok":true,"message":"OK","api_version":1}
```

Базовый ответ с ошибкой:

```json
{"ok":false,"message":"error text","api_version":1}
```

## Поддерживаемые команды IPC

### status

Проверяет, что демон запущен.

```json
{"api_version":1,"command":"status"}
```

### shutdown

Запрашивает штатную остановку демона.

```json
{"api_version":1,"command":"shutdown"}
```

### module_list

Возвращает список модулей.

```json
{"api_version":1,"command":"module_list"}
```

Ответ содержит дескрипторы модулей. `view` принимает только `standard`,
`device` или `audit` и является клиентской метаинформацией, не влияющей на
применение политик:

```json
{"modules":[{"name":"AUDIT","view":"audit"},{"name":"DAC","view":"standard"},{"name":"DC","view":"device"}]}
```

### policy_list

Возвращает политики одного модуля или всех модулей.

```json
{"api_version":1,"command":"policy_list","module":"all"}
```

```json
{"api_version":1,"command":"policy_list","module":"DAC"}
```

Ответ содержит поле `policies`. Для каждой политики возвращаются данные для
стандартного редактора: `module`, `submodule`, `policy`, `enabled`, `set`,
`value`, `default_value`, `editor`, `validator`, `possible_values`, `restriction` и
применимые `min`, `max`, `text_delimiter`. `view` здесь не дублируется.
`editor` определяет вид контрола, а `validator` независимо задаёт клиентскую
валидацию (`none`, `integer_range`, `unsigned_integer`, `allowed_values`).

### set_policy_value

Изменяет значение политики в конфигурации.

```json
{"api_version":1,"command":"set_policy_value","module":"DAC","policy":"sudo_timeout","value":"10"}
```

После успешного изменения демон перечитывает конфигурацию.

### enable_policy

Включает политику.

```json
{"api_version":1,"command":"enable_policy","module":"DAC","policy":"sudo_timeout"}
```

После успешного изменения демон перечитывает конфигурацию.

### disable_policy

Отключает политику.

```json
{"api_version":1,"command":"disable_policy","module":"DAC","policy":"sudo_timeout"}
```

После успешного изменения демон перечитывает конфигурацию.

### reload_config

Принудительно перечитывает конфигурацию.

```json
{"api_version":1,"command":"reload_config"}
```

### apply_all

Немедленно применяет все включенные политики.

```json
{"api_version":1,"command":"apply_all"}
```

### apply_module

Немедленно применяет все включенные политики указанного модуля.

```json
{"api_version":1,"command":"apply_module","module":"DAC"}
```

### apply_policy

Немедленно применяет одну политику.

```json
{"api_version":1,"command":"apply_policy","module":"DAC","policy":"sudo_timeout"}
```

Все команды применения возвращают сводку и отдельный результат для каждой
политики. В `diagnostics` находятся записи `Logger`, созданные во время
конкретного вызова `Policy::apply()` и прошедшие текущий `AUDIT/log_level`:

```json
{
  "ok": false,
  "message": "Не удалось применить политику",
  "diagnostics_truncated": false,
  "summary": {"total": 1, "applied": 0, "failed": 1, "disabled": 0, "not_found": 0},
  "results": [{
    "module": "DAC",
    "submodule": "Sudo",
    "policy": "sudo_timeout",
    "status": "failed",
    "message": "Не удалось применить политику",
    "diagnostics": [{
      "timestamp": "2026-07-12 12:00:00.000 +0300",
      "level": "ERROR",
      "category": "daemon",
      "message": "Не удалось сохранить файл"
    }],
    "diagnostics_truncated": false
  }]
}
```

Захват ограничен 128 записями и 64 КиБ на одну политику. Общий объем
диагностик в одном IPC-ответе ограничен 256 КиБ. Если один из лимитов
достигнут, соответствующий флаг `diagnostics_truncated` равен `true`.

`AUDIT/log_level` управляет только обычными записями через `Logger`. Отдельный
security audit trail административных IPC-запросов записывается напрямую через
`write_audit_log()` и остается always-on при любом уровне, включая `NoLog`.
Команды чтения `boot_id` и `log_records` исключены из audit trail отдельно,
чтобы polling не сдвигал пагинацию журнала; это исключение не является
фильтрацией по `log_level`.

Security audit хранится в формате JSON Lines: одна запись является одним
самостоятельным JSON-объектом на одной физической строке. Для IPC-записей
объект содержит `timestamp`, `component`, typed `peer`, `command`, whitelist
`request` и `result`. Строковые значения ограничены 240 байтами, итоговая
запись — 16 КиБ; усечённые значения перечисляются в `truncated_fields`.
Расширение audit-файлов остаётся `.txt`, поскольку `log_records` передаёт их
строки как opaque log text и не разбирает внутренний формат.

`status=applied` означает не только успешную операцию записи. Политика
возвращает успех, когда persistent-состояние перечитано и подтверждено, а все
физически возможные и безопасные без перезагрузки runtime-эффекты применены и
проверены. Частичное применение возвращает `failed`; выполненные и не
выполненные стадии описываются в diagnostics. Опасные действия активации,
например remount работающих файловых систем, намеренно не выполняются.

### calc_hash

Пересчитывает hash для указанного пути.

```json
{"api_version":1,"command":"calc_hash","value":"/usr/bin/sudo"}
```

### lock, unlock, lockstatus

Команды управления блокировкой.

```json
{"api_version":1,"command":"lock"}
```

```json
{"api_version":1,"command":"unlock"}
```

```json
{"api_version":1,"command":"lockstatus"}
```

## Systemd

Основной unit находится в:

```text
fic/src/resources/service/fic.service
```

Сервис запускает демон как постоянный процесс:

```text
ExecStart=/opt/fic/bin/fic --interval 1800
```

Периодичность находится внутри постоянного daemon process; отдельный systemd
timer не устанавливается.

## Конфигурация и данные

### Целевая платформа

Daemon собирается ровно для одного дистрибутива. CMake требует явный
`FIC_TARGET_PLATFORM`: `debian-12`, `debian-13`, `ubuntu-24.04` или `alt-p11`.
Неизвестное или отсутствующее значение останавливает конфигурацию CMake.

Выбранный профиль создается в `fic/src/platform/profiles/` и передается в
`initPolicyRegistry()`. Он является единым источником системных путей, executable-
кандидатов и имен service units. Политики не выбирают дистрибутив через
локальные `#ifdef`.

Профиль содержит независимые секции:

- `executables`: единый типизированный реестр кандидатов `sshd`, `systemctl`,
  `loginctl`, `visudo`, `lscpu`, `dmidecode` и `udevadm`;
- `packageManager`: тип пакетной базы (`dpkg` или RPM) и кандидаты
  bootstrap query-инструмента;
- `ssh`: основной конфиг, база `Include` и service units;
- `sudo`: основной и managed-конфиги sudoers;
- `pam`: каталоги PAM-конфигурации и модулей, целевые authentication/password
  services и канонические конфиги поддерживаемых providers;
- `displayManager`: конфиги SDDM, LightDM и упорядоченные кандидаты GDM;
- `dac`: точные наборы системных файлов и команд с владельцем, группой и
  правами.

Политики обращаются к командам через логические идентификаторы
`ExecutableId`, а не перебирают пути самостоятельно. Один общий
`PlatformExecutableResolver` выбирает первый пригодный кандидат и кэширует
выбор. Перед возвратом пути он проверяет, что это абсолютный нормализованный
обычный исполняемый файл, а не симлинк, что файл принадлежит root и недоступен
на запись группе или остальным. Кэшированный путь повторно проверяется при
каждом обращении.

Основные различия текущих профилей:

| Профиль | SSH | GDM | shell/GRUB в DAC | `ip` в DAC |
| --- | --- | --- | --- | --- |
| Debian 12 | `/etc/ssh/sshd_config`, `ssh.service` | `/etc/gdm3/daemon.conf` | `/etc/bash.bashrc`, `/boot/grub/grub.cfg` | `/usr/sbin/ip` |
| Debian 13 | `/etc/ssh/sshd_config`, `ssh.service` | `/etc/gdm3/daemon.conf` | `/etc/bash.bashrc`, `/boot/grub/grub.cfg` | `/usr/sbin/ip` |
| Ubuntu 24.04 | `/etc/ssh/sshd_config`, `ssh.service` | `/etc/gdm3/custom.conf` | `/etc/bash.bashrc`, `/boot/grub/grub.cfg` | `/usr/sbin/ip` |
| ALT p11 | `/etc/openssh/sshd_config`, `sshd.service` | `/etc/gdm/custom.conf` | `/etc/bashrc`, `/etc/grub.cfg` → `/boot/grub/grub.cfg` | `/sbin/ip` |

Если первый GDM-конфиг отсутствует, используются только следующие кандидаты из
того же compile-time профиля. Это проверка установленного пакета внутри
выбранного дистрибутива, а не runtime-переключение дистрибутива.

При старте daemon проверяет выбранный профиль и `/etc/os-release`. Эта проверка
не выполняет runtime-автоопределение и не переключает профиль: несовместимый
пакет завершается с ошибкой до создания сокета и применения политик.
`fic --version` показывает product SemVer, compile-time идентификатор профиля,
версию IPC API и схему конфигурации. `fic --build-info` дополнительно выводит
тип сборки, полный commit, release tag и независимые версии IPC,
конфигурационной и SQLite-схем; commit не является частью SemVer.

SSH-секция определяет основной конфигурационный файл, базу относительных
`Include`, service и socket units и ожидаемый для пакета тип маршрутизации SSH в PAM;
фактическую capability подтверждает доверенный `sshd`. `sshd` и `systemctl`
поступают из общего реестра `executables`. Один профиль используется
редактированием, rollback, `sshd -T`,
include-аудитом и reload.

Команды конкретных desktop environment (`gsettings`, `kwriteconfig`,
`xfconf-query`, Fly), XDG-путь `/run/user`, `/etc/fstab`, `/proc/sys` и
стандартные каталоги sysctl не являются выбором дистрибутива. Они остаются
capability-, FHS- или kernel-зависимыми и не дублируются в профилях.
Системный `nft` является обязательным executable профиля и разрешается через
тот же `PlatformExecutableResolver`; пакеты daemon зависят от `nftables`.

Production layout определяется в `cmake/FicInstallLayout.cmake`. C++ не
содержит собственных копий `/opt/fic` и `/run/fic`: CMake генерирует defaults,
а демон один раз инициализирует `FicRuntimePaths` при старте. Те же переменные
используются для генерации systemd/tmpfiles/udev-файлов и install rules.

Пути являются независимыми по назначению. Для нестандартной сборки следует
передавать конкретные `-DFIC_CONFIG_DIR=...`, `-DFIC_LOG_DIR=...`,
`-DFIC_RUNTIME_DIR=...` и остальные параметры layout, а не вводить общий
prefix/root, который смешивает изменяемые данные, конфигурацию и runtime.

Основные runtime-пути:

- `/opt/fic/share/default-config` - package-owned неизменяемые шаблоны конфигурации;
- `/opt/fic/config` - конфигурационные файлы политик;
- `/opt/fic/log` - логи;
- `/run/fic` - общий runtime-каталог IPC, создаваемый через `fic.conf` для systemd-tmpfiles;
- `/run/fic/fic.sock` - Unix-сокет демона.

Обычный запуск использует административный профиль сокета и проверяет
`root:root 0755` у runtime-каталога и `root:fic 0660` у сокета. `--socket PATH`
предназначен для разработки: создаваемый сокет имеет режим `0600`, и демон не
перенастраивает production-каталог.

Каждый конфиг модуля начинается с `_schema_version=1`. Это первая и единственная
поддерживаемая схема: daemon отклоняет конфиги без точной текущей версии.
`fic --maintenance ensure-config` атомарно создаёт только отсутствующие рабочие
конфиги из package defaults и не перезаписывает существующие файлы.
`fic --maintenance check-config` выполняет строгую проверку schema 1. Старые
development-конфиги автоматически не преобразуются. Полный контракт описан в
`docs/upgrade-contract.md`.

### Безопасная запись конфигурации

Однофайловые обработчики принимают `FileHandlerOptions` и передают общую
политику записи в `AtomicFileWriter`. Для существующего файла можно сохранить
его `uid`/`gid`/режим либо принудительно установить заданные метаданные. Запись
остается атомарной: временный файл, `fsync`, `rename` и `fsync` каталога.

Отсутствующие файлы по умолчанию не создаются. Явное создание с принудительными
метаданными используется для `/etc/sysctl.conf` (`root:root`, `0644`),
конфигурации display manager (`root:root`, `0644`), хранилища hash команд
(`/opt/fic/db/commandhash.txt`, `root:<group of /opt/fic/db>`, `0640`) и
managed-файла sudoers (`root:root`, `0440`). Исходные файлы sudoers, SSH,
`/etc/fstab`, конфигурация политик и файлы локализации при отсутствии считаются
ошибкой и не создаются во время чтения.

### Работа с sudoers

Политики подмодуля `SudoEdit` читают не только `/etc/sudoers`, но и активный
граф директив `@include`, `#include`, `@includedir` и `#includedir`.
Источники проверяются в том порядке, в котором их обрабатывает sudoers; в
диагностику применения включаются путь и номер строки.

Политики глобальных параметров `Defaults` не переписывают файлы
администратора. Их эталон записывается в управляемый файл:

```text
/etc/sudoers.d/zzzz-fic
```

Каталог `/etc/sudoers.d` должен быть подключен из основной конфигурации, а
managed-файл должен определять итоговое значение. Если после include находятся
перекрывающие директивы, применение завершается ошибкой и изменение
откатывается. FIC не добавляет include-директиву в `/etc/sudoers` автоматически.

Политика `sudo_require_authentication` имеет другую семантику: она точечно
заменяет `NOPASSWD` на `PASSWD`, включает `authenticate` и отключает
`exempt_group` в тех активных локальных sudoers-файлах, где обнаружено
нарушение. Пользователи, группы, `RunAs`, хосты и разрешенные команды не
изменяются. Политика не очищает timestamp-кэш sudo и не анализирует PAM,
LDAP/SSSD или другой внешний источник правил.

Составные строки с несколькими `Host_Spec` и многострочные правила с `\\`,
которые отключают аутентификацию, в первой версии намеренно не переписываются:
политика завершается безопасной ошибкой с путем и номером строки. Это исключает
частичное изменение сложного правила; администратор может предварительно
разделить его на отдельные однострочные записи. Перед записью проверяется весь
include-граф: если неподдерживаемое правило найдено хотя бы в одном источнике,
ни один файл не изменяется. Если ошибка возникает уже во время последовательной
записи или проверки `visudo`, ранее записанные файлы откатываются.

Перед любой записью конфигурация проверяется через `visudo`. Путь валидатора
выбирается общим platform resolver по `ExecutableId::Visudo`, а запуск
выполняется через `VerifiedProcessExecutor`. Эталонный hash выбранного файла
заполняется package-transaction trust sync. Отсутствующий hash или ошибка
`visudo` приводят к безопасному отказу без заявления об успешном применении.
На Ubuntu 26.04 resolver сначала определяет активный sudo provider по
root-owned alternatives selector `/usr/bin/sudo`: sudo-rs сопоставляется с
`/usr/lib/cargo/bin/visudo`, а classic sudo — с `/usr/sbin/visudo.ws`.
Наличие parser-а неактивного provider не является основанием для fallback;
неизвестный provider или отсутствие соответствующего validator завершаются
безопасным отказом.

### Identity and access

Модуль `IDENTITY_ACCESS` разделён по владельцам системной конфигурации:
`PAM`, `SSSD`, `KERBEROS`, `NSS` и `COMPOSITE`. Классы
`PamPolicy`, `SssdPolicy`, `KerberosPolicy` и `NssPolicy` задают границу
подмодуля и наследуются от `IdentityAccessPolicy`; парсеры и редакторы
системных конфигураций от `Policy` не наследуются. Зарегистрированы следующие
конкретные политики:

- политики качества пароля управляют `minlen`, `minclass`, `usercheck`,
  `gecoscheck`, `difok`, флагом `enforce_for_root` и минимальным числом
  символов каждого класса через `lcredit`, `ucredit`, `dcredit`, `ocredit`
  активного `pam_pwquality`; пользовательские минимумы классов остаются
  неотрицательными, а FIC преобразует положительное `N` в native `-N`;
- `password_history_depth` и `password_history_enforce_for_root` управляют
  соответственно `remember` и флагом `enforce_for_root` активного
  `pam_pwhistory`;
- `failed_authentication_attempts`,
  `failed_authentication_counting_period` и
  `failed_authentication_unlock_time` управляют соответственно `deny`,
  `fail_interval` и `unlock_time`, а
  `failed_authentication_enforce_for_root` — флагом `even_deny_root` активного
  `pam_faillock`;
- `sssd_offline_credentials_expiration` задаёт срок допустимости offline-login
  по кешированным credentials в `[pam]`. Если `sssd.service` активен, изменение
  применяется через restart в одной компенсирующей транзакции с записью файла;
- `kerberos_ticket_lifetime` задаёт `ticket_lifetime` в `[libdefaults]` в
  секундах. Уже выданные билеты политика не перевыпускает.

`CompositePolicy` предназначен для одной политики, затрагивающей несколько
подсистем. Он не хранит и не запускает вложенные `Policy`: leaf-политика сначала
регистрирует независимые `ConfigurationParticipant`. Каждый participant
готовит полностью проверенный `PreparedConfigurationChange`, после чего общий
координатор выполняет persistent commit, persistent verification, runtime
activation и effective verification. При ошибке все начатые изменения
откатываются в обратном порядке, runtime восстанавливается и rollback
проверяется. Это компенсирующая транзакция; атомарные `rename` отдельных файлов
не обеспечивают crash-atomicity всего набора. Для восстановления после падения
между двумя commit потребуется отдельный журнал, которого в текущем каркасе
нет.

Все leaf- и composite-политики используют один identity-configuration mutex,
чтобы анализ и изменение PAM/SSSD/Kerberos/NSS не выполнялись конкурентно
внутри daemon. Базы `SssdPolicy`, `KerberosPolicy` и `NssPolicy` владеют
соответствующим typed configuration editor и передают его в hook конкретной
политики.

Редакторы намеренно различаются по грамматике и не используют общий INI
парсер:

- `SssdConfiguration` сохраняет структуру основного `sssd.conf`, читает
  `.conf` snippets в заданном порядке каталогов и лексикографическом порядке
  внутри каталога. Если изменяемая настройка определена в snippet, редактор
  отказывает до записи вместо создания скрытого override;
- `KerberosConfiguration` изменяет только скалярные relations верхнего уровня,
  обходит абсолютные `include`/`includedir`, сохраняет final markers и
  отказывает при внешнем определении изменяемой relation, цикле либо profile
  `module`. Вложенные realm/dictionary relations этим API не редактируются;
- `NssConfiguration` работает с типизированным списком NSS services и action
  blocks (`[STATUS=ACTION]`, включая отрицание), сохраняя комментарии и
  посторонние databases.

Все три редактора требуют существующий обычный файл, проверяют владельца,
группу, режим, лимит размера и отсутствие symlink во всей цепочке пути.
Подготовленное изменение повторно сверяет snapshot непосредственно перед
атомарной записью и не затирает более позднюю внешнюю правку при rollback.
Их `set*()` выполняет только file-level transaction: перезапуск SSSD,
инвалидация кеша и другие runtime-действия являются обязанностью конкретного
policy participant. `SssdOfflineCredentialsExpirationPolicy` выполняет это
требование через `SssdRuntime`: неактивная служба не запускается, активная
перезапускается, а ошибка restart вызывает rollback файла и повторный restart
с восстановленной конфигурацией.

### Работа с PAM

Это намеренно не универсальный редактор `/etc/pam.d`. PAM composition строится
по цепочке `logical policy → capability → provider backend → config grammar →
topology strategy → platform profile`. Профиль декларативно задаёт независимые
capabilities `PasswordQuality`, `PasswordHistory` и `AuthenticationLockout`,
их service scope, provider, config path и topology strategy. Policy-классы не
ветвятся по идентификатору дистрибутива. `PamProviderCatalog` является единым
источником provider → capability/module/config-argument/grammar/policy binding;
platform profile выбирает provider, но не дублирует его grammar.

`PamConfiguration` строит effective-граф каждой существующей целевой службы с
учётом `@include`, `include` и `substack`, ограничивает глубину и размер графа и
отклоняет циклы или неподдерживаемый синтаксис. `PamProviderInspector`
сопоставляет модуль с provider descriptor, в том числе использует правильное
имя внешнего config-аргумента: `conf=` для pwquality/faillock/pwhistory и
`config=` для passwdqc. Descriptor также задаёт, является argument optional
или required. Для управляемого passwdqc `config=/etc/passwdqc.conf` обязателен:
отсутствующий, повторный, относительный либо отличный от platform path argument
отклоняется. У key/value providers `conf=` остаётся optional. Одновременное
присутствие двух providers одной capability является конфликтом.

Registry создаётся по support map выбранной composition. Поэтому pwquality-only
политики не показываются на passwdqc-платформе, а passwdqc-native политики — на
pwquality-платформе. Общая `password_quality_enforce_for_root` отображается
backend'ом в `enforce_for_root` для pwquality и в `enforce=everyone|users` для
passwdqc. `pam_cracklib`, `pam_tally*` и `pam_unix remember=` распознаются как
альтернативные providers, но не получают приблизительных mappings.
Неподдерживаемый policy ID не регистрируется: его наличие в устаревшем config
не создаёт скрытую no-op policy, а запросы mutation/apply получают штатный
ответ `policy does not exist`.

Generated `IDENTITY_ACCESS.conf` также строится по mechanism composition:
quality/history defaults выбираются по provider capabilities, а не по literal
platform id. Поэтому synthetic `passwdqc+pwhistory` и `pwquality` без history
не требуют distro-specific ветки в central `fic/CMakeLists.txt`.

| Платформы | Capability | Provider | Config grammar | Topology |
| --- | --- | --- | --- | --- |
| Debian 12/13, Ubuntu 24.04/26.04 | PasswordQuality | pam_pwquality | key/value | `PamAuthUpdate`: FIC-owned `fic-pwquality`; distro `pwquality` is external/compliant |
| Debian 12 | PasswordHistory | pam_pwhistory | module arguments | `PamAuthUpdate`: `fic-pwhistory` |
| Debian 13, Ubuntu 24.04/26.04 | PasswordHistory | pam_pwhistory | key/value | `PamAuthUpdate`: `fic-pwhistory` |
| Debian 12/13, Ubuntu 24.04/26.04 | AuthenticationLockout | pam_faillock | key/value | `PamAuthUpdate`: strategy recipes `fic-faillock-notify`/`fic-faillock-preauth-required` + `fic-faillock-authfail`, `fic-faillock-authsucc` + `fic-faillock-authfail` |
| ALT p11 | PasswordQuality | pam_passwdqc | strict `option=value` | `StaticVerifyOnly` native topology |
| ALT p11 | AuthenticationLockout | pam_faillock | key/value | `AltTcbManaged`: `AltPamFaillockTopologyManager` |
| ALT p11 | PasswordHistory | pam_pwhistory | key/value в `/etc/security/fic-pwhistory.conf` | `AltTcbManaged`: serialized TCB transaction |

ALT p11 хранит историю в `/var/lib/fic-pwhistory/opasswd` и сериализует общую
history update вместе с последующей записью `pam_tcb` через
`pam_fic_pwtxn.so`. Пакетная конфигурация содержит `remember=0`, поэтому одна
установка пакета не включает enforcement. Политика
`enable_password_history` подключает topology, а history option policies
отдельно задают `remember` и `enforce_for_root`.

`enable_password_history` и `enable_password_quality` имеют фиксированное
значение `ENABLE`. `enable_authentication_lockout` — стратегическая политика:
её значение выбирает интеграцию pam_faillock. Debian/Ubuntu поддерживают
`preauth_requisite`, `preauth_required` и `authsucc`; ALT p11 поддерживает
только `preauth_requisite` и `preauth_required`, поскольку его внешний
service stack может отказать уже после возврата из управляемого
`system-auth*` substack, где `authsucc` преждевременно сбросил бы tally.
Поддерживаемый набор и значение по умолчанию объявлены в platform profile
(`supportedFaillockStrategies`, `defaultFaillockStrategy`, для Debian/Ubuntu —
также `strategyActivations`).
Capability без объявленных стратегий считается на платформе неподдерживаемым:
политика активации не регистрируется, а попытка применения отклоняется.
Смена стратегии выполняется одной операцией платформы: snapshot состояния
pam-auth-update (`/var/lib/pam`) и generated `common-*` файлов, один вызов
`pam-auth-update` с `--disable`/`--enable`, повторная проверка exact strategy
для всех целевых служб и восстановление snapshot при любой ошибке применения
или проверки; неудача rollback возвращает CRITICAL диагностику. Топология
без FIC profile selection в state database считается внешней: она может
анализироваться, но FIC не меняет её стратегию и не накладывает поверх неё
свои profiles. Ownership определяется по profile selection state, а стратегия
должна быть одинаковой во всех целевых службах (иначе topology Broken).
Activation policies при необходимости вызывают native integration, затем
создают новую `PamConfiguration` и выполняют `PamCapabilityVerifier` в режиме
`Structural`. Успешный exit code native tool
без корректного resulting effective graph считается ошибкой. Выключенный
status такой FIC policy означает только отсутствие обеспечения со стороны FIC
и никогда не запускает деактивацию PAM mechanism. Все option policies имеют
Recommended dependency на соответствующую activation policy, но сохраняют
собственный fail-closed Structural preflight и exact postcondition.

Debian 12 хранит history settings в arguments существующего
`pam_pwhistory.so`: отсутствие `remember=` означает native default 10, а
явный `remember=0` считается ineffective. Остальные поддерживаемые
Debian/Ubuntu profiles используют provider config file.

PAM service symlink по умолчанию запрещены. ALT p11 profile точечно описывает
штатные selectors `/etc/pam.d/system-auth`, `/etc/pam.d/system-policy` и их
exact allowlists package-owned targets через `PamTrustedServiceAlias`.
Resolver не следует по alias обычным
pathname API: target должен быть basename в том же PAM directory, открывается
через `openat(..., O_NOFOLLOW)`, проверяется по type/owner/mode и повторно
сверяется после чтения. Произвольные top-level и included symlink по-прежнему
отклоняются.

Для `pam_faillock` дополнительно требуется одна из двух полных непротиворечивых
topology: `authfail` + `authsucc` (с необязательным `preauth`) либо `preauth` +
`authfail` + вызов в группе `account`. Дубли, неполные цепочки, другой provider
хотя бы в одной целевой службе и отсутствие provider приводят к fail-closed
ошибке до записи.

После preflight проверяются тип, владелец и права всех посещённых PAM
service/include-файлов и используемых `.so`, внешний config-аргумент и inline
options, способные перекрыть управляемое значение. Key/value providers меняет
`PamOptionFile`; passwdqc использует отдельные typed parser/evaluator/writer.
Parser принимает native leading/trailing whitespace, comments, assignments и
flags, но не принимает неизвестные либо невалидные параметры. Повторные
assignments вычисляются последовательно по native last-wins semantics.
`config=` рекурсивно загружается в месте появления; глубина и общий input
ограничены, loop, missing/relative path, symlink, non-regular либо небезопасно
доступный nested file приводят к fail-closed. Сложный `min` разбирается typed
codec'ом как пять невозрастающих числовых/`disabled` полей. Writer заменяет
только управляемую root-directive в canonical `option=value`, после чего
повторно вычисляет весь effective state.

`PamOptionPolicy` держит общую transaction boundary: snapshot raw config и
metadata → mutation → effective file postcondition → повторная проверка PAM
graph/provider. Любая ошибка после записи восстанавливает исходный файл и
проверяет rollback; невозможность rollback возвращает failure с CRITICAL
диагностикой о потенциально degraded PAM state.

На ALT p11 package-level topology `pam_faillock` управляется отдельно от
policy values. Facility `control fic-pam-faillock enabled|disabled` вызывает
offline manager основного `fic`, а activation policy вызывает тот же
authoritative `AltPamFaillockTopologyManager` напрямую. Manager изменяет только platform targets:
`/etc/pam.d/system-auth-local-only` с ролью authentication+account и отдельный
authentication path `/etc/pam.d/system-auth-use_first_pass-local-only`.
Роли и пути заданы typed platform metadata; имена файлов manager не выводит
строковой заменой. В каждом target используются отдельные FIC-owned markers и
сохраняется именно его исходная строка `pam_tcb`, включая `use_first_pass`.
Обе записи охвачены одним inter-process lock и verified multi-file rollback
exact original bytes. Semantic postcondition через `PamCapabilityVerifier`
проверяет основной local stack и configured services, чья auth-ветка реально
проходит через дополнительный target (на штатном ALT p11 — `sshd`). Это не
расширяет проверку на посторонние ветки штатного `sss` router. Перед записью effective
include/substack graph проверяется на внешний
`pam_faillock`, а `pam_tcb` должен быть последним исполняемым auth rule.
Operational error самого `pam_faillock preauth`, который завершает stack
fail-closed, не классифицируется как обход `authfail`; credential failure,
завершившийся до достижения `pam_faillock`, по-прежнему считается обходом.
Штатная ALT/GDM строка `auth sufficient pam_succeed_if.so user ingroup
nopasswdlogin` является отдельным typed trusted bypass
`ExplicitPasswordlessLogin`: matcher требует exact service `gdm-password`,
source, simple control и ordered arguments. Evidence сохраняется отдельно и
не выдаётся за executed `pam_faillock`. Политика `disable_nopasswdlogin`
административно запрещает этот путь: при files-only `passwd`, `group` и
явном `initgroups` NSS она оставляет
отсутствующую/пустую группу без изменений либо очищает supplementary members
через hash-verified `gpasswd`; primary GID и внешний NSS приводят к fail-closed.
При штатном ALT `sss` в NSS policy не пытается перечислять доменных
пользователей: она атомарно удаляет exact typed passwordless PAM bypass из
объявленных GDM/LightDM services, проверяет отсутствие всех таких bypass и
восстанавливает exact исходные bytes при ошибке записи или postcondition.
Она является Recommended dependency только для lockout/authentication PAM
policies, поэтому её warning не блокирует основную policy.
Moved managed blocks и заменённый после snapshot target inode любого target
отклоняются без записи. Внешняя topology никогда не присваивается FIC.
Штатный ALT `pam_passwdqc` остаётся без FIC activation facility: его уже
подключённая native topology проверяется как local-only `PasswordQuality` в
`system-auth-local-only`; SSS password branch не обязана содержать passwdqc.
FIC управляет
native settings `min`, `passphrase`, `match`, `similar`, `retry` и enforcement
scope; pwquality-only `minlen`, `minclass`, `difok`, user/GECOS checks и class
credits на ALT отсутствуют. `pam_pwhistory` активируется отдельной facility
`control fic-pam-pwhistory enabled|disabled`.

При отключении `failed_authentication_enforce_for_root` параметр
`root_unlock_time` считается конфликтом, потому что в `pam_faillock` он сам
подразумевает `even_deny_root`. FIC отказывает до записи вместо удаления
независимой настройки администратора или заявления о неэффективном `no`.

`pam_pwquality minlen` — provider-native параметр, а не самостоятельное
доказательство фактической длины пароля: на итоговую проверку могут влиять
остальные credit-параметры libpwquality. Политика гарантирует effective
значение `minlen`, но не выдает его за полный аудит всех правил качества.
`password_min_classes` остаётся независимой от четырёх минимальных class
policies: FIC применяет заданные значения без взаимного изменения. Для них
логическое значение `0` записывается как native credit `0`, а положительное
`N` — как `-N`; тем самым bonus и обязательный минимум соответствующего
класса при нуле отключены.

### Реагирование на инциденты

Политика `GLOBAL/lock_settings/incident_response_mode` задаёт способ реакции
независимо от сохранённого `/opt/fic/lockstatus`. При `DISABLE` режим `OFF`:
новые события не повышают severity, не создают incident audit/notification и
не запускают containment. При `ENABLE` и значении `PASSIVE` (заводской default)
severity сохраняется, SecurityAudit и уведомления выполняются, но входы,
сессии, пользовательские процессы и сеть не блокируются. При значении
`ACTIVE` к тем же действиям добавляется containment по severity. Сохранённый
`HARD` остаётся `HARD` при переходе в `PASSIVE`/`OFF`; обратимые блокировки
FIC снимаются, а ранее завершённые процессы и сессии не восстанавливаются.
Переход обратно в `ACTIVE` применяет containment к уже сохранённой severity.
Административный `incident clear` доступен в любом режиме.

Device-detector события идут по той же единой подсистеме: `fic-dick` сообщает
факт отсутствия permanent-устройства через команду `incident_device_missing`
(только `device_ids`, без severity), основной daemon проверяет peer credentials
(только root-UID device daemon), резолвит реакцию из политики
`DC/DeviceControl/permanent_device_missing_severity` (NONE/SOFT/STANDARD/HARD/
ISOLATE; заводской default STANDARD) и вызывает `IncidentController.raise()`.
`NONE` и `DISABLE` не создают incident state; `OFF` не выполняет audit/
notification/containment. Недоказуемая настройка (политика отсутствует,
статус не ENABLE/DISABLE, значение отсутствует или не распознано) является
fail-closed: реакция `ISOLATE` через `IncidentController.raise()`, а не
намеренное игнорирование. Восстановление устройства не снижает severity и не
вызывает автоматический clear.

Ответ daemon'а формируется единым production-билдером
(`fic::daemon::make_device_incident_ack_response`) и несёт три независимых
утверждения: `acknowledged` (обязательство доставки детектора закрыто),
`persistence_confirmed` (требуемая severity долговременно сохранена —
фактический результат `IncidentStateStore::raiseToAtLeast()`) и `incident_ok`
(совокупная успешность, включая containment). Для намеренно игнорируемого
события (DISABLE/NONE/OFF): `acknowledged=true`, `persistence_confirmed=false`,
`ignored=true` — нового обязательства записи нет, и это не ошибка.
`acknowledged=true` не доказывает успешный containment: `DEGRADED`-containment
при подтверждённой персистенции даёт `acknowledged=true`,
`persistence_confirmed=true`, `incident_ok=false`, сообщение
`device incident recorded; containment degraded` и не запускает повторную
доставку — за containment отвечает сам IncidentController. Неудачная
персистенция даёт `device incident could not be recorded` и не подтверждает
доставку.

`pam_fic_access.so` установлен постоянно. В `OFF`/`PASSIVE` он нейтрален и
не требует работающего daemon. Только в `ACTIVE` обычный контролируемый вход
зависит от daemon и fail-closed при недоступности, `DEGRADED` или severity
`STANDARD` и выше; локальный root recovery и существующая recovery-group
семантика сохраняются. Единый доверенный resolver читает `GLOBAL.conf` как
security authority. Отсутствующий, повреждённый или недоверенный файл означает
fallback `ACTIVE`, а не автоматическое смягчение режима. Только `ACTIVE`
условно требует `NET/SshEdit/ssh_use_pam`; эта Required dependency участвует
в планировании применения и диагностике policy API.

В `ACTIVE` контроллер получает инвентаризацию сессий из systemd-logind через
системный D-Bus и выбирает цели containment по **Model A**: целями являются
только реально существующие обычные login-сессии, доказанные logind.
Доказанно пустой ответ отличается от ошибки logind: ошибка даёт `DEGRADED`,
сохраняя записанную severity.

Критерий выбора цели — **положительные доказательства**, а не предположения о
назначении Linux-аккаунтов: session получена из logind; её класс — обычный
login class (`user`, `user-early`, `user-light`, `user-early-light`); UID и
username согласованы с NSS; identity не изменилась с момента inventory; это
не root и не защищённая recovery identity (членство в recovery-группе при
включённом `lock_exempt_fic_members` проверяется успешно). **Login shell,
UID-диапазоны (`UID_MIN`/`UID_MAX`), имя пользователя и перечисление
`/etc/passwd` не участвуют в выборе цели**; NSS используется только для
подтверждения identity и recovery membership. Следствие Model A: учётная
запись службы с настоящей login-сессией (`Class=user`) — сознательная цель,
а пользователь с только lingering user manager и без выбранной обычной
login-сессии целью не становится никогда.

`manager`, `background` и `background-light` сами по себе не создают цель, но
могут принадлежать уже выбранному обычному пользователю и завершаться как
часть его user runtime при `ISOLATE`. `manager-early`, `greeter`,
`lock-screen` и неизвестные классы защищены; неизвестный класс делает
inventory недоказанным (`DEGRADED`), не допуская действий вслепую.

`STANDARD` запрашивает блокировку графической сессии, но ответ logind и
`LockedHint` не доказывают фактическую блокировку desktop, поэтому backend
сразу переходит к `TerminateSession` и проверяет исчезновение той же session
через logind. SSH/TTY завершаются без lock. `HARD` завершает все выбранные
обычные login-сессии через `TerminateSession` и не вызывает `TerminateUser`.
`ISOLATE` дополнительно выполняет `TerminateUser` и проверяет исчезновение
logind user и остановку `user@UID.service`. Сетевой карантин реализован через единый FIREWALL coordinator; описание профилей и ограничений — в разделе «Работа с FIREWALL».

### Durable session target store (Model A)

`TerminateSession` уничтожает само доказательство выбора пользователя, поэтому
новый инцидент сначала фиксирует **пустое новое поколение** в отдельном durable-хранилище
`incident_session_targets` (рядом с `lockstatus`, root-owned, 0640, atomic
replace, fsync файла и каталога; schema 2 содержит lifecycle marker, `boot_id`,
`incident_generation` и evidence выбора: session id, класс, timestamp).
Это делается при первом raise из доказанного `UNLOCKED` для любого ненулевого
уровня, включая `SOFT` и `PASSIVE`, **до** записи нового `lockstatus`.
Каждая выбранная цель затем фиксируется в этом поколении до разрушающего
действия. Если durable fencing или регистрация не
подтверждена — `TerminateSession` удерживается, результат `DEGRADED`;
`persistenceConfirmed` отражает только фактический результат записи severity.
При неудаче fencing контроллер пытается
записать durable `BROKEN_STATE` и запрещает session/user mutations.

Это даёт: повторный `reconcile()` и эскалация `HARD → ISOLATE` используют
сохранённые цели даже после исчезновения login-сессий; перезапуск FIC
восстанавливает pending-обязательства из store; проверенное ядро reboot
разрешает runtime-обязательства предыдущей загрузки (процессы не могли
пережить смену `boot_id`; systemd soft-reboot с тем же `boot_id` их
сохраняет). При `ISOLATE` каждый pending-UID повторно доказывается через NSS
(UID ↔ canonical name): повторное использование UID другим аккаунтом
блокирует действие и даёт `DEGRADED`, а не успех. `ListUsers` больше не
является источником новых целей — только механизмом выполнения и
подтверждения user-level containment уже выбранных UID.

`Discharged` фиксирует исполненное обязательство, но не является постоянным
доказательством отсутствия user runtime. При каждом `ISOLATE` reconciliation
ранее выбранные `Discharged` targets проверяются заново. Если runtime по-прежнему
доказанно отсутствует, запись не меняется. Если logind заново обнаруживает
runtime того же доказанного пользователя, FIC сначала durably переводит
обязательство в `Pending`, затем повторно проверяет identity и выполняет
`TerminateUser` с независимой проверкой результата. Новая обычная login-сессия
того же UID также обновляет evidence и фиксирует `Pending` **до**
`TerminateSession`. Ранее не выбранный lingering-only пользователь не становится
целью. При недостоверной проверке или неуспешной записи re-arm результат
`DEGRADED`, изменяющее действие запрещено. После рестарта durable `Pending`
сохраняется, а `Discharged` снова требует свежей проверки. Периодический
reconciliation подтверждает состояние на момент проверки; он не обеспечивает
непрерывный атомарный запрет повторного запуска runtime. Если manager кажется
активным, но logind не даёт доказанной identity для `TerminateUser`, FIC
сообщает `DEGRADED` и не завершает UID вслепую.

Административный clear сначала фиксирует `UNLOCKED`, затем очищает targets;
сбой cleanup виден в ответе при сохранённом факте durable `UNLOCKED`.
Два файла не образуют атомарную транзакцию: авария между fencing и severity
оставляет `UNLOCKED`, а авария после severity оставляет доказанное пустое
поколение. После аварии между `UNLOCKED` и cleanup следующий инцидент
обязательно фиксирует новое пустое поколение до своей severity. Смена
kernel `boot_id` при активном инциденте выполняет durable rebase с пустыми
targets до обработки сессий нового boot; обычный restart FIC/logind при том
же `boot_id` сохраняет pending obligations. Отсутствующий, повреждённый или
старой схемы store при активном инциденте даёт `DEGRADED` без session/user
mutations. Повторная
проверка identity и D-Bus-действие по-прежнему разделены узкой гонкой (API
logind не даёт атомарной операции), что остаётся задокументированным
ограничением. `OFF` и `PASSIVE` не выполняют никаких мутаций сессий и
пользователей, clear не разблокирует экраны. Проверки ограничены timeout и
объёмом inventory. Это доказательство logind-managed состояния выбранных
пользователей, а не всех процессов всех обычных пользователей Linux.

### Работа с SSH

Модуль включает политики `ssh_port`, `ssh_max_auth_tries`, `ssh_root_login`,
`ssh_pubkey_auth` и `ssh_use_pam`. `ssh_pubkey_auth` имеет фиксированное
значение `yes`: включенная политика обеспечивает `PubkeyAuthentication yes`,
но не отключает парольную аутентификацию. `ssh_use_pam` также имеет
фиксированное значение `yes` и включена в новой конфигурации по умолчанию.

При управляемом переходе `OFF`/`PASSIVE` → `ACTIVE` FIC сначала закрывает
объявленные SSH service/socket entry points, затем записывает новый режим в
`GLOBAL.conf`, применяет Required `ssh_use_pam` и доказывает prerequisite.
Если запись не удалась и прежний режим всё ещё доказуемо неактивен, временная
блокировка снимается только по подтверждённому ownership. Неудача любого
последующего этапа оставляет внутреннее состояние `DEGRADED` и SSH закрытым;
административный IPC остаётся доступен. `sd_notify READY=1` сообщает systemd
о запуске daemon, а не о готовности IncidentAccessGate. Редактирование значения
`ACTIVE` при `DISABLE` не создаёт перехода и не блокирует SSH.
При старте с `ACTIVE`, включая fallback при недоверенном `GLOBAL.conf`, SSH
закрывается до startup apply. При выходе в `PASSIVE`/`OFF` сохранённый
`lockstatus` не меняется.
Внешняя запись `GLOBAL.conf` вне daemon IPC не синхронизирована с ним: следующий
периодический проход закрывает SSH перед apply, но момент такой записи FIC
контролировать не может.

При входе в `ACTIVE` FIC доказывает `UsePAM=yes` через доверенный `sshd -T`,
проверяет `PAMServiceName=sshd` во всех допустимых `Match`/`Include` контекстах
на поддерживающих его OpenSSH и постоянную topology `pam_fic_access.so`.
Поддерживается узкая штатная service/socket topology из `PlatformProfile`:
доверенный `/usr/sbin/sshd`, стандартный `ExecStart` и пустые дополнительные
параметры в доверенном package option file. Неизвестное явное окружение,
`PassEnvironment`, custom `-f`/`-o`, executable или socket target оставляют
ACTIVE prerequisite недоказанным. Кроме unit environment, проверяется
`systemctl --system show-environment`: разрешены только простые `LANG` и
штатные значения `PATH` поддерживаемых платформ; иные переменные, ошибки,
экранирование или изменение блока при активации дают `DEGRADED`. Проверка
не исполняет вывод как shell. Это сравнение снимков до и после операции:
кратковременное изменение с возвратом прежнего значения между чтениями
неразличимо без атомарного контракта со стороны systemd. Активный штатный
service управляемо
перезапускается; неактивный не запускается ради доказательства. После restart
проверяются активность service, `MainPID`, доверенный `/proc/MainPID/exe`,
эффективный SSH config и PAM topology.

FIC не восстанавливает исторические argv/environment работающего OpenSSH master
по `/proc/PID/cmdline` или `/proc/PID/environ`: OpenSSH перезаписывает их при
`setproctitle`. В `ACTIVE` отдельная проверка каждые 30 секунд повторно
проверяет простой текущий invariant без restart при здоровом состоянии. Если
он недоказан, daemon остаётся доступен для администратора в `DEGRADED`,
контролируемые PAM-входы fail-closed, а FIC останавливает объявленные SSH
service/socket units, пишет security audit и уведомляет. После восстановления
prerequisite FIC включает только те listeners, для которых доказал собственную
остановку. Witness `/run/fic/incident-ssh-block` хранит точные unit names,
boot ID и состояние `intent`/`stopped`; перед stop атомарно фиксируется intent,
для всех изначально активных service/socket units, поскольку остановка socket
может одновременно остановить service. После подтверждения inactive
фиксируется completed stop. Файл `root:root`, `0600`,
в защищённом `/run/fic`; это runtime ownership текущего boot, а не persistent
policy. После crash новый daemon читает witness до restore. Изначально
inactive/failed/deactivating units не становятся FIC-owned. Неоднозначный
`intent`, недоверенный witness или неудачный restore не дают права автоматически
запускать SSH и оставляют `DEGRADED`; при частичном восстановлении успех не
объявляется. В `PASSIVE`/`OFF` активная блокировка не устанавливается, но
FIC снимает доказанную ранее собственную блокировку. При неоднозначном witness
локальный root-администратор должен остановить daemon FIC, проверить состояние
unit и PAM/SSH config, восстановить нужный SSH listener вручную и только затем
удалить witness перед повторным запуском FIC;
слепой `systemctl start` FIC не выполняет. Отдельно запущенные вне объявленных
units процессы `sshd` не входят в этот контракт.

Политики SSH после атомарной записи перечитывают `sshd_config`, получают все
эффективные значения через `sshd -T` и перезагружают активный `ssh.service` или
`sshd.service`. Скалярный параметр должен иметь ровно одно ожидаемое effective-
значение. Для `Port` допускается только один ожидаемый порт; дополнительно
проверяются порты в effective-значениях `ListenAddress`.

Так как один запуск `sshd -T` без параметров соединения не раскрывает все
условные значения, FIC отдельно просматривает основной файл и полный граф
`Include`, включая вложенные условные include. Ослабляющее или неоднозначное
переопределение контролируемого параметра внутри `Match` делает применение
неуспешным. Эквивалентное или доказуемо более строгое значение допускается:
для `PermitRootLogin` используется порядок `no`, `forced-commands-only`,
`prohibit-password`, `yes`, а для `MaxAuthTries` меньшее положительное число
считается более строгим. Алиас OpenSSH `without-password` считается
эквивалентным `prohibit-password`. Циклический, слишком глубокий или чрезмерно
большой include-граф обрабатывается fail-closed с указанием источника.

Разбор строк основного файла и read-only аудит используют общий SSH-синтаксис:
поддерживаются разделители `Keyword Value`, `Keyword=Value` и их варианты с
пробелами, кавычки, escape и inline-комментарии. Состояние `Match` наследуется
включенным файлом, но восстанавливается после каждого `Include`, как это делает
OpenSSH. Повторяющиеся директивы, не относящиеся к изменяемой политике, при
записи основного файла не комментируются.

Если SSH-сервис не активен, runtime reload не требуется. Ошибка effective-
проверки или аудита `Match`/`Include` откатывает изменение файла; ошибка reload
оставляет проверенную persistent-конфигурацию на диске, но применение политики
считается неуспешным как частичное.

`sshd` и `systemctl` выбираются общим platform resolver и запускаются через
`VerifiedProcessExecutor`. Hash рассчитывается автоматически при установке и
после пакетных транзакций для executable, выбранных compile-time профилем. Например,
ALT p11 использует `/usr/sbin/sshd`, а Debian 12, Debian 13 и Ubuntu 24.04
допускают профильные кандидаты `/usr/sbin/sshd` и `/usr/bin/sshd`.

Команда `fic --trust-sync-platform` доступна только root и не является IPC API.
Она выбирает пути через общий resolver, требует владельца root и безопасные
права, подтверждает принадлежность файла пакету и сверяет его содержимое с
checksum в локальной базе `dpkg` или RPM. Только если проверены все доступные
кандидаты, их новые SHA-256 значения одним атомарным сохранением добавляются в
`/opt/fic/db/commandhash.txt`; отсутствующая необязательная системная утилита
пропускается. На merged-/usr системах пакетный `/bin/...` принимается как
алиас выбранного `/usr/bin/...` только при совпадении device/inode.

Служебная команда `fic --trust-list-platform-paths` выводит все candidates из
скомпилированного `profile.executables.entries` и используется Debian/Ubuntu
packaging для генерации точных `dpkg` file triggers. При их активации postinst
передает имена сработавших путей в
`fic --trust-sync-platform-affected`.

ALT-пакет устанавливает нативный исполняемый
`/usr/lib/rpm/fic-trust-sync.filetrigger`, который передает полный полученный от
RPM список измененных файлов в тот же affected-режим. Он сопоставляет пути со
всеми candidates профиля, группирует совпадения по `ExecutableId` и не
обращается к пакетной базе и hash store при отсутствии совпадений. Для
совпавших записей проверяются и атомарно обновляются только выбранные
executable; устаревшие hashes их прежних candidates удаляются в той же
операции. Первичная полная синхронизация выполняется до включения сервисов.
Ошибка пакетной проверки останавливает hook и не меняет ни один эталон.

Обычный daemon runtime намеренно не авторизует новый hash: отсутствие эталона
или mismatch по-прежнему приводит к fail-closed отказу. `fic-cli hash calc`
сохраняется как явная административная break-glass операция, но для штатной
установки и обновления больше не требуется.

### Работа с FIREWALL

FIREWALL имеет два взаимоисключающих effective profile. Единственная authority —
`IncidentController::networkQuarantineRequired()`: `ACTIVE + ISOLATE` выбирает
`INCIDENT_QUARANTINE`, остальные сочетания — `NORMAL`. Недоказанная severity
эффективно равна ISOLATE, недоказанный response mode — ACTIVE. При неудачной
персистенции контроллер также публикует более строгую текущую effective ISOLATE
requirement, даже если старый корректный token остался на диске. FIREWALL не
изменяет severity. Production `FirewallIncidentNetworkAdapter` только передаёт
запрос общему `FirewallCoordinator`, не исполняя nft-команды самостоятельно.

В `NORMAL` действуют `block_rdp`, `block_ftp`, `custom_rules` и
`exclusive_firewall_control`. Первые две и exclusive policy управляются только
статусом. Обычные правила имеют `policy accept` в отдельных таблицах
`inet fic_block_rdp`, `fic_block_ftp`, `fic_custom_rules`. Direct ordinary apply
меняет только выбранную policy; полный reconciliation строит все правила из
текущего `FIREWALL.conf`. `incident_quarantine` в NORMAL не устанавливает правил,
а её dormant значение не влияет на ordinary enforcement.

В `INCIDENT_QUARANTINE` ordinary FIC tables отсутствуют, включая их DROP rules:
разрешения карантина не блокируются собственными обычными политиками FIC.
`inet fic_incident_quarantine` содержит три base chains `input`, `output`,
`forward`: type `filter`, соответствующий hook, priority `0`, policy `drop`.
Это IPv4/IPv6 default-deny для текущего network namespace. Loopback разрешён
по `iifname/oifname lo` только в input/output. Forward исключений не имеет.
Пустой список не разрешает SSH, DNS, DHCP, NTP, LAN или старые established flows.

Новая policy `FIREWALL/HostFiltering/incident_quarantine` («Минимальный сетевой
доступ при блокировке ОС») задаёт только исключения. Заводские настройки:

```ini
incident_quarantine.status=ENABLE
incident_quarantine.value=[]
```

ENABLE использует явно заданные allow exceptions. **DISABLE означает отключение
исключений, а не обязательного карантина**: ISOLATE сохраняет DROP и loopback.
Внешняя/повреждённая конфигурация исключений означает попытку доказанного
строгого карантина и одновременно ошибку/DEGRADED, даже если fallback установлен.
Статусы, metadata, schema, повторяющиеся и неоднозначные ключи configuration
проверяются через `SecureStateFile` и config authority.

JSON использует общий parser `custom_rules`: массив до 1024 rules и 256 KiB,
ровно семь полей, IPv4/IPv6 IP или CIDR (host bits нормализуются), одинаковая
family source/destination, строгие типы и отсутствие raw nft script:

```json
[
  {
    "direction": "outgoing",
    "protocol": "tcp",
    "source": "any",
    "destination": "192.0.2.10",
    "source_port": "any",
    "destination_port": 443,
    "action": "allow"
  }
]
```

`direction`: `incoming|outgoing`; `protocol`: `any|tcp|udp`;
`source/destination`: `any|IP|CIDR`; ports: `any`, integer 1..65535 или строка
`first-last` с возрастающими границами. При protocol any порты обязаны быть any.
Карантин принимает только `action=allow`; `block` отвергается.
Каждое исключение допускает выбранный tuple в своём направлении, а в обратном
направлении — только `ct state established`, `ct direction reply` **и обратный
address/port/protocol tuple того же исключения**. Общего established/related
accept нет. Старое соединение к неразрешённому endpoint остаётся заблокированным;
соединение, соответствующее явно разрешённому tuple, может продолжаться.
RELATED/ICMP errors автоматически не разрешаются.

При исключениях, допускающих IPv6, добавляются только Neighbor Solicitation и
Neighbor Advertisement (ICMPv6 types 135/136, code 0, hoplimit 255) в input/output.
При пустых или IPv4-only исключениях их нет. Router Advertisement, DHCPv6 и
произвольный ICMPv6 не разрешены. Доступность IPv6 требует уже настроенных
адресов/маршрутов; PMTU и router discovery эта первая версия полностью не
обеспечивает. ND не является разрешением общего IP-трафика.

Все backend entry points (`applyPolicy`, `applyExclusive`, `reconcile`), startup,
manual apply_all/module/policy и ordinary rollback проходят coordinator.
Во время карантина ordinary config остаётся редактируемой, ordinary apply
подтверждает effective quarantine и сообщает deferred enforcement в diagnostics;
нового ordinary mutation obligation о несуществовавшем kernel apply не возникает.
Journaled apply сериализован с выбором profile. Incident policy не получает
ordinary rollback record; удаление ordinary tables при входе в карантин сохраняет
существующие obligations. При восстановлении NORMAL физическое создание обычных
policy-owned tables требует journal provenance, даже если его инициировали
profile transition, startup, periodic/full reconciliation или direct backend apply.

**Ownership manifest не заменяет mutation journal.** Manifest доказывает право
backend менять конкретные nft objects; `UndoRemoveFirewallPolicy` доказывает
rollback authority соответствующей Policy. После проверки actual state и manifest
общая physical execution boundary заново доказывает durable journal и проверяет
весь effective NORMAL plan. Для отсутствующей таблицы без active record готовится
новый durable Prepared. Все missing obligations нескольких политик готовятся
**до** ownership intent и единого nft batch. Existing Applied/Prepared/
RollbackFailed record сохраняет тот же id, без дубликатов; RollbackFailed diagnostic
не стирается no-op reconciliation. Уже существующая даже manifest-proven таблица
без journal record — provenance conflict, автоматического принятия нет.

Порядок: kernel inspection + ownership proof → durable journal preparations всех
ordinary resources → durable ownership intent → один checked nft transaction →
independent complete postcondition → durable Prepared→Applied completion.
Journal и manifest — два отдельных файла, а не общая атомарная транзакция.
Crash/failure до kernel apply оставляет Prepared без ложного Applied; неизвестный
результат batch/postcondition также сохраняет Prepared. Retry/restart перечитывает
persistent journal/manifest и повторно доказывает kernel: отсутствующая таблица
создаётся под прежним active id, совпадающая таблица разрешает тот же Prepared
без нового nft write. Partial journal commit означает failure/DEGRADED; оставшиеся
Prepared не теряются и завершаются после fresh proof. Proven no-op с Applied
не переписывает запись. Empty custom_rules не создаёт table и новый record.

Administrative disable после восстановления идёт через обычный production
`rollbackPolicyBeforeDisable()`, journal и coordinator. Removal-only rollback
удаляет только выбранную owned table: он не восстанавливает отсутствующие таблицы
других policies и не применяет exclusive control. Во время ISOLATE он сохраняет
карантин, затем DISABLE config исключает policy из будущего NORMAL restoration.
Ошибка ordinary journal не ослабляет уже установленный quarantine. NORMAL
restoration, создающий ordinary resources, отказывается при journal error и
сообщает failure; durable UNLOCKED сохраняется. Empty NORMAL cleanup, которому
не нужны ordinary creations, может удалить owned quarantine независимо от journal.

Переключение профиля, обновление исключений и возврат в NORMAL используют один
JSON nft batch: необходимые удаления и создания находятся в одной kernel
transaction. Он проверяется `nft -j -c -f -`, применяется `nft -j -f -` через
существующий trusted resolver/`VerifiedProcessExecutor`, после чего независимый
`nft -j list ruleset` доказывает **все** managed tables, chains, hooks, priorities,
policies и ordered expressions. Только kernel handles не входят в semantic
сравнение; неожиданные поля, объекты, chains или rules не считаются успехом.
Удаление таблицы адресуется её наблюдённым kernel handle. Failed check/apply или
неполная/неподдерживаемая JSON/postcondition дают ошибку, не network proof.
Неизменный ruleset не пересоздаётся.

Ownership — отдельный root-owned 0640 `firewall_ownership` рядом с `lockstatus`,
в защищённом product directory. Он содержит versioned before/after maps полной
структуры FIC объектов и случайные 128-bit nonce в rule comments. Intent durably
публикуется atomic replace + file/parent fsync **до** nft apply. Это позволяет
распознать before/after после crash до/после transaction или verification;
комментарий без manifest и полной структуры ничего не доказывает.
Имя не даёт ownership. Старые таблицы без manifest и чужие/изменённые объекты
зарезервированного `fic_` пространства не принимаются автоматически, не удаляются
и дают DEGRADED. Это сознательное deployment ограничение; automatic adoption
legacy tables отсутствует. Повреждённый manifest также не заменяется вслепую.

`exclusive_firewall_control` работает только в NORMAL: атомарно нейтрализует
foreign inet/ip/ip6 filter/route base chains input/output, оставляя таблицы,
NAT, FORWARD, bridge и netdev. Удалённые foreign rules не восстанавливаются при
DISABLE. В карантине exclusive не применяется и foreign objects остаются
нетронутыми. При возврате в NORMAL текущий ENABLE снова включает exclusive.
Accept FIC не гарантирует связь, если её запрещает независимый foreign firewall.

Administrative clear сначала фиксирует durable UNLOCKED, затем восстанавливает
NORMAL из **текущей** конфигурации, включая изменения/rollback во время ISOLATE.
Ошибка восстановления сохраняет UNLOCKED и DEGRADED, retry выполняется reconcile.
OFF/PASSIVE также восстанавливают NORMAL после restart без in-memory ownership
flags. Persistent ISOLATE переустанавливает quarantine после kernel reboot.
Periodic apply и существующая bounded readiness проверка (30 секунд при ACTIVE
ISOLATE) обновляют proof/drift; это периодический контроль, не continuous
anti-root enforcement. Controller transitions и FIREWALL operations используют
общий in-process lock; внешние привилегированные writers всё ещё могут менять
state между proof и mutation/после verification.

Scope этой реализации — inet filtering одного network namespace. ARP и non-IP
L2 traffic, bridge/netdev hooks, другие namespaces, existing flowtables и hardware
offload полного containment не получают. Их обход нельзя считать заблокированным
этим профилем. Внешний service reload также может удалить rules; требуется
следующий reconciliation. Полного L2 или мгновенного anti-drift containment
реализация не заявляет.

Исполняемые проверки: `firewall_incident_profile_tests` использует production
coordinator/backend над fake nft transport и реальный IncidentController;
`--kernel-tests` и `packet_tests.py` предназначены **только** для disposable
Podman namespace с соответствующими capabilities. Фактический результат текущей
validation записан в `docs/HANDOFF.md`.

### Работа с sysctl

Политики `SYSCTL` моделируют порядок procps-ng `sysctl --system`. Они отбирают
активные `*.conf` из `/etc/sysctl.d`, `/run/sysctl.d`,
`/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d` и `/lib/sysctl.d`: файл с
одинаковым именем берется только из каталога с наивысшим приоритетом, после чего
выбранные файлы читаются в общем лексикографическом порядке. `/etc/sysctl.conf`
читается последним.

Политика `kernel_sysrq_disable` фиксированно устанавливает
`kernel.sysrq = 0`. Это отключает управляемые через sysctl команды Magic SysRq,
но не может перекрыть параметр ядра `sysrq_always_enabled`: если он присутствует
в загруженном ядре, политика не имеет эффекта.

Нарушением считается только итоговое значение параметра. Противоречащая строка
в раннем файле не исправляется, если она уже перекрыта правильным более поздним
значением. При реальном отклонении FIC не меняет файлы пакетов или локального
администратора по месту: эталон добавляется в управляемый блок в конце
`/etc/sysctl.conf`:

```text
# BEGIN FIC MANAGED SYSCTL
kernel.dmesg_restrict = 1
# END FIC MANAGED SYSCTL
```

Перед записью проверяется, что активный набор файлов не изменился. Запись
атомарна, файл получает `root:root 0644`, затем конфигурация перечитывается и
проверяется, что managed-значение действительно стало итоговым. Некорректная
активная строка, небезопасные права, неоднозначный managed-блок или ошибка
постусловия приводят к безопасному отказу; после неуспешной проверки запись
откатывается.

При вычислении точного параметра учитываются glob-назначения (`*`, `?`, `[]`),
строки исключения вида `-key` без `=` и правило, по которому явное назначение
ключа исключает его из glob-совпадений. Префикс `-` в обычной строке
`-key = value` трактуется как ignore-failure, а не как исключение.

Перед изменением persistent-конфигурации FIC проверяет наличие соответствующего
параметра в `/proc/sys`. После записи managed-блока runtime-значение изменяется
прямой записью в фиксированный путь `/proc/sys`, без запуска shell или
`sysctl`. Имя ключа валидируется, symlink запрещен, а записанное значение
перечитывается. Отсутствующий параметр, ошибка записи или несовпадение после
записи приводят к неуспешному применению политики. Если persistent-конфигурация
уже была исправлена, а runtime-применение завершилось ошибкой, файл остается
подготовленным, но итог политики остается `failed`.

### Работа с GRUB

`OSS/Grub` — общая граница для политик `grub_timeout`,
`grub_cmdline_linux` и `grub_disable_recovery`. Финальный `Grub::apply()`
валидирует значение политики и сериализует операции всех GRUB-политик одним
mutex. Общий редактор изменяет соответствующее присваивание в
явно заданной compile-time topology. На Debian/Ubuntu FIC не изменяет общий
`/etc/default/grub`: политики ведут целиком принадлежащий FIC файл
`/etc/default/grub.d/zzzz-fic.cfg` со строгим набором допустимых ключей. На
ALT p11 сохраняется безопасное редактирование shared-файла
`/etc/sysconfig/grub2`. Затем запускается
`update-grub` без аргументов на Debian/Ubuntu или
`grub-mkconfig -o /etc/grub.cfg` на ALT p11. Путь команды разрешается через
единый реестр проверяемых исполняемых файлов.

Shared-редактор ALT принимает только простые статические shell-присваивания.
Managed-редактор Debian/Ubuntu принимает только FIC marker, комментарии, пустые
строки и уникальные присваивания `GRUB_TIMEOUT`, `GRUB_CMDLINE_LINUX` и
`GRUB_DISABLE_RECOVERY`; файл при записи канонически регенерируется. Оба пути
безопасно отказывают при динамическом shell, symlink, небезопасных
владельце/правах или необычном типе файла. Для owned topology наличие любого
применимого `*.cfg`, загружаемого после `zzzz-fic.cfg`, блокирует изменение.
Даже если исходное значение уже совпадает, генератор запускается: это
синхронизирует потенциально устаревший сгенерированный `grub.cfg`.

Хотя FIC не редактирует `/etc/default/grub`, `update-grub` по-прежнему
исполняет его как shell-код от root. Поэтому профиль задаёт его как
validate-only `baseDefaultsPath`, и перед любой мутацией managed drop-in —
включая idempotent apply — этот файл проверяется: отсутствие файла допустимо,
существующий файл обязан быть обычным не-symlink файлом ограниченного размера
без group/world write, принадлежать root (при enforceOwnership) и лежать в
безопасной цепочке каталогов (group/world write запрещены, world-writable
допустим только со sticky-битом). Небезопасный `/etc/default/grub` означает
fail closed без мутации managed-файла и без запуска генератора.

Запись выбранного topology-файла атомарна. После неё файл перечитывается и
проверяется.
Если первая генерация завершается ошибкой, исходный файл восстанавливается и
генератор запускается повторно для компенсирующего восстановления загрузочной
конфигурации. Компенсация выполняется только если текущее состояние файла
в точности совпадает с состоянием, которое FIC только что установил
(снапшот устанавливается самим atomic writer'ом); внешнее изменение файла
между записью и сбоем генерации классифицируется как concurrent-drift
конфликт: внешнее состояние сохраняется, исходное не восстанавливается,
файл не удаляется, компенсирующая генерация не запускается. Ошибка самого
применения или восстановления возвращается как
неуспешный результат политики; FIC не заявляет crash-atomicity двух файлов.

## Сборка

Из корня проекта:

```bash
cmake -S . -B build-check
cmake --build build-check --target fic
```

Отдельная сборка компонента:

```bash
cmake -S fic -B build-fic
cmake --build build-fic
```

## Зависимости

Компонент использует:

- C++17;
- OpenSSL Crypto;
- nlohmann/json;
- POSIX Unix-сокеты.

## Взаимодействие с другими компонентами

- `fic-cli` отправляет команды администрирования через socket API.
- `fic-gui` отправляет изменения политик через socket API.
- `fic-dick --daemon` обслуживает дерево устройств через `/run/fic/fic-device.sock`,
  владеет `/opt/fic/db/devices.db` и вызывает команду `lock` в `fic` при нарушении
  правила `permanent`.
- Ручные правила контроля устройств задают желаемое состояние. Если администратор
  помечает уже подключенное устройство как `blocked`, `fic-dick` не отключает его
  немедленно; блокировка применяется при следующем подключении или переподключении.
- Низкоуровневые общие утилиты находятся в `fic-common/fic-core`; внутренний код подключает их через `<fic/core/...>`.
- Базовые классы политик, результат применения и типы значений находятся в `fic-common/fic-policy`; конкретные политики модулей остаются в `fic/src/modules`.

## Важные правила разработки

- Новые операции изменения конфигурации должны добавляться в daemon API, а не в CLI или GUI напрямую.
- После изменения конфигурации демон должен перечитывать `policyMap`, чтобы последующие операции работали с актуальным состоянием.
- Новые socket-команды должны возвращать единый JSON-формат с полями `ok` и `message`.
- CLI и GUI не должны получать прямую запись в `/opt/fic/config`.

### Pre-Login Gate

Опциональный пакет `fic-prelogin` удерживает штатный DM через systemd до ручного
или доказанного автоматического handoff. Это отдельный экран, не authentication
provider; handoff не отключает PAM и не меняет Incident Response.
Графический frontend использует системный Qt EGLFS/KMS от отдельного
непривилегированного пользователя; broker подтверждает его завершение перед
освобождением DM. При отсутствии DRM доступен текстовый recovery на tty7.
Контракт status API, lifecycle установки/удаления и recovery описаны в
[`fic-prelogin/README.md`](../fic-prelogin/README.md).
