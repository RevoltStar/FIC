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

`log_records` является постраничной командой: принимает `offset` от 0 и
`limit` от 1 до 500, возвращает `has_more` и, если данные остались,
`next_offset`. Одна страница дополнительно ограничена 768 КиБ; отдельная строка
лога перед отправкой ограничивается 16 КиБ и помечается `line_truncated`.

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
`Include` и service units; `sshd` и `systemctl` поступают из общего реестра
`executables`. Один профиль используется редактированием, rollback, `sshd -T`,
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
| Debian 12/13, Ubuntu 24.04/26.04 | PasswordQuality | pam_pwquality | key/value | external opt-in/static PAM stack |
| Debian 12 | PasswordHistory | pam_pwhistory | module arguments | external opt-in через pam-auth-update |
| Debian 13, Ubuntu 24.04/26.04 | PasswordHistory | pam_pwhistory | key/value | external opt-in через pam-auth-update |
| Debian 12/13, Ubuntu 24.04/26.04 | AuthenticationLockout | pam_faillock | key/value | external opt-in через pam-auth-update |
| ALT p11 | PasswordQuality | pam_passwdqc | strict `option=value` | native static topology |
| ALT p11 | AuthenticationLockout | pam_faillock | key/value | FIC-owned ALT/tcb manager, explicit opt-in |
| ALT p11 | PasswordHistory | pam_pwhistory | key/value в `/etc/security/fic-pwhistory.conf` | FIC-owned serialized TCB transaction, explicit opt-in |

ALT p11 хранит историю в `/var/lib/fic-pwhistory/opasswd` и сериализует общую
history update вместе с последующей записью `pam_tcb` через
`pam_fic_pwtxn.so`. Пакетная конфигурация содержит `remember=0`, поэтому одна
установка пакета не включает enforcement; администратор сначала активирует
topology через `control fic-pam-pwhistory enabled`, затем применяет history
policy.

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
policy values через `control fic-pam-faillock enabled|disabled`. Facility
вызывает offline manager основного `fic`; daemon policies сами facility не
активируют. Manager изменяет только platform targets:
`/etc/pam.d/system-auth-local-only` с ролью authentication+account и отдельный
authentication path `/etc/pam.d/system-auth-use_first_pass-local-only`.
Роли и пути заданы typed platform metadata; имена файлов manager не выводит
строковой заменой. В каждом target используются отдельные FIC-owned markers и
сохраняется именно его исходная строка `pam_tcb`, включая `use_first_pass`.
Обе записи охвачены одним inter-process lock и verified multi-file rollback
exact original bytes. Semantic postcondition через `PamCapabilityVerifier`
проверяет основной local stack и configured services, чья auth-ветка реально
проходит через дополнительный target (на штатном ALT p11 — `sshd`). Это не
расширяет проверку на посторонние ветки штатного `sss` router; глобальная policy
`required_pam_enforcement` не ослабляется. Перед записью effective
include/substack graph проверяется на внешний
`pam_faillock`, а `pam_tcb` должен быть последним исполняемым auth rule.
Moved managed blocks и заменённый после snapshot target inode любого target
отклоняются без записи. Внешняя topology никогда не присваивается FIC.
Штатный ALT `pam_passwdqc` остаётся без FIC activation facility: его уже
подключённая native topology проверяется как `PasswordQuality`. FIC управляет
native settings `min`, `passphrase`, `match`, `similar`, `retry` и enforcement
scope; pwquality-only `minlen`, `minclass`, `difok`, user/GECOS checks и class
credits на ALT отсутствуют. Активация `pam_pwhistory` на ALT не поддерживается
до появления безопасного storage contract для истории паролей.

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

### Работа с SSH

Модуль включает политики `ssh_port`, `ssh_max_auth_tries`, `ssh_root_login` и
`ssh_pubkey_auth`. Последняя имеет фиксированное значение `yes`: включенная
политика обеспечивает `PubkeyAuthentication yes`, но не отключает парольную
аутентификацию. Встроенное фиксированное значение используется и при обновлении
старой установки, в `NET.conf` которой еще нет строки `ssh_pubkey_auth.value`;
пользовательский конфигурационный файл при этом не переписывается.

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

FIREWALL v1 использует только nftables и четыре обычные Policy:
`block_rdp`, `block_ftp`, `custom_rules` и `exclusive_firewall_control`.
Первые две и exclusive policy управляются только статусом; `.value` для них в
`FIREWALL.conf` отсутствует. `custom_rules.value` — нормализованный JSON-массив
правил `incoming`/`outgoing` для IPv4/IPv6 с протоколами `any`, `tcp`, `udp` и
действиями `allow`, `block`. Одиночный порт задаётся JSON integer, диапазон —
строкой `first-last`, отсутствие ограничения — строкой `any`. При протоколе
`any` оба порта должны быть `any`; одновременно заданные source и destination
должны принадлежать одной IP family.

Каждая конфигурируемая policy владеет отдельной таблицей `inet`:
`fic_block_rdp`, `fic_block_ftp` или `fic_custom_rules`. Base chains имеют
`policy accept`, поэтому FIREWALL v1 не вводит default DROP. Обычный
`policy apply FIREWALL <policy>` атомарно заменяет только таблицу выбранной
policy. Скрипт сначала проверяется `nft -c -f -`, затем передаётся тому же
проверенному executable через `nft -f -`; временные файлы не используются.

В daemon startup/periodic pass FIREWALL исключается из generic цикла отдельных
`Policy::apply()`: daemon отдельно загружает `FIREWALL.conf`, строит полный
desired state и одним nft batch удаляет stale FIC-owned tables и пересоздаёт
включённые. Это не меняет IPC apply одной Policy или всего модуля. Отдельного ENABLE/DISABLE-состояния
модуля нет: если все четыре Policy выключены, reconciliation продолжается и
удаляет все три FIC-owned tables.

При `exclusive_firewall_control=ENABLE` reconciliation дополнительно находит
только чужие base chains семейств `inet`, `ip`, `ip6`, типов `filter`/`route`
и hooks `input`/`output`. Каждая такая влияющая цепочка очищается и атомарно
пересоздаётся с теми же family/table/name/type/hook/priority и `policy accept`.
Целая таблица и её остальные цепочки не удаляются; NAT, FORWARD, bridge и
netdev не изменяются. После отключения exclusive policy дальнейшая
нейтрализация прекращается, но удалённые сторонние правила автоматически не
восстанавливаются. Это намеренное ограничение FIREWALL v1.

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
каноническом defaults-файле compile-time профиля: `/etc/default/grub` на
Debian/Ubuntu и `/etc/sysconfig/grub2` на ALT p11. Затем запускается
`update-grub` без аргументов на Debian/Ubuntu или
`grub-mkconfig -o /etc/grub.cfg` на ALT p11. Путь команды разрешается через
единый реестр проверяемых исполняемых файлов.

Редактор принимает только простые статические shell-присваивания. Он декодирует
одинарные и двойные кавычки, записывает новое значение как экранированный
двойной quoted literal и безопасно отказывает при дублирующих присваиваниях,
динамических shell-выражениях, symlink, небезопасных владельце/правах или
необычном типе файла. Даже если исходное значение уже совпадает, генератор
запускается: это синхронизирует потенциально устаревший сгенерированный
`grub.cfg`.

Запись профильного defaults-файла атомарна. После неё файл перечитывается и
проверяется.
Если первая генерация завершается ошибкой, исходный файл восстанавливается и
генератор запускается повторно для компенсирующего восстановления загрузочной
конфигурации. Ошибка самого применения или восстановления возвращается как
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
