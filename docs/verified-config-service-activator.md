# VerifiedConfigServiceActivator

## Назначение и граница ответственности

`fic/src/service/VerifiedConfigServiceActivator.h` предоставляет самостоятельный
C++17-компонент однократной контролируемой активации systemd-службы. Компонент
проверяет уже установленную конфигурацию, временно публикует проверенный снимок,
перезапускает службу и освобождает временные mount. Постоянные файлы он не
редактирует. Существующие политики, SSH, planner, MutationJournal и rollback
компонент не вызывают; их контракты не изменены.

Это **не постоянная защита конфигурации**. После cleanup администратор может
изменить файлы или перезапустить службу. Это не отменяет результат предыдущей
завершённой операции. Позднее перечитывание конфигурации службой не защищается.

## API

```cpp
using namespace fic::service;
ActivationRequest request;
request.unit = "example.service";
request.timeout = std::chrono::seconds(10);
request.paths = {
    {"/etc/example.conf", ControlledPathKind::File, expectedSha256, {}},
    {"/etc/example.d", ControlledPathKind::Directory, "", {
        {"first.conf", firstSha256}, {"sub/second.conf", secondSha256}
    }}
};
ActivationResult result = VerifiedConfigServiceActivator::activate(request);
```

SHA-256 — 64 lowercase hex-символа. `FileManifest` — упорядоченный map относительных
имён обычных файлов в SHA-256. Он задаёт точный набор файлов: отсутствующие,
лишние и изменённые файлы запрещены. Каталоги выводятся из предков имён файлов;
неожиданные пустые подкаталоги запрещены. Пустой корневой каталог допустим.
Вызывающий код отвечает за полноту списка источников конфигурации службы.

`ActivationResult` содержит:

| Поле | Смысл |
| --- | --- |
| `status` | Итог с учётом cleanup; только `Success` означает успех |
| `primaryStatus` | Результат до собственных unmount, сохраняется при ошибке cleanup |
| `diagnostic` | Основная диагностическая строка |
| `cleanupErrors` | Все обнаруженные ошибки освобождения |
| `residualPaths` | Пути mount/каталогов, требующих проверки администратором |
| `readinessConfirmed` | Готовность была подтверждена перед cleanup; сама по себе не означает успех |

Статусы: `Success`, `ChecksumMismatch`, `UnsupportedConfiguration`,
`SnapshotFailed`, `MountFailed`, `InterferenceDetected`, `RestartFailed`,
`ReadinessUnconfirmed`, `TimedOut`, `CleanupFailed`, `ResidualMounts`.
Например, успешный restart с неудачным unmount возвращает `CleanupFailed`,
`primaryStatus=Success`, `readinessConfirmed=true`, а не успешную операцию.

## Поддерживаемая конфигурация и preflight

Первая версия намеренно ограничена следующими условиями:

* Linux с procfs, tmpfs, `statx(STATX_MNT_ID)` (Linux 5.8+), mount namespaces;
  root с эффективным `CAP_SYS_ADMIN` в initial user namespace и правами чтения/копирования атрибутов.
* systemd — PID 1; активатор, manager и MainPID службы имеют один mount
  namespace и совместимый корень файловой системы.
* Канонический загруженный `.service`, уже `active/running`, без pending Job,
  только `Type=notify`, `NotifyAccess=main`; неактивная служба не запускается.
* Недопустимы root image/directory, private mount sandbox, bind/path restrictions,
  временные FS и проверяемые `Protect*`/`Private*` ограничения. Неизвестные или
  отсутствующие необходимые systemd properties означают отказ. При подтверждении
  нового MainPID снова проверяются namespace, root и process starttime.
* `systemctl` разрешается через `PlatformExecutableResolver`; его hash уже должен
  находиться в доверенном `CommandHashStore`. Автоматического enrollment нет.
* Абсолютные нормализованные пути без symlink на любом уровне; все родительские
  каталоги root-owned без group/world write. Запрещены пересечения целей, `/`,
  пересечение с рабочим каталогом, существующие mount на цели и вложенные mount.
* Только обычные файлы и каталоги. Копируются UID/GID, permissions 0777 и timestamps;
  hardlink topology не сохраняется. Special permission bits, xattrs, ACL,
  security labels и enforcing SELinux отклоняются до mount. Это ограничение
  предотвращает молчаливую потерю атрибутов чтения/доступа.
* До 16 целей, до 4096 записей manifest на каталог, до 8192 объектов обхода и
  глубина до 64. `maxSnapshotBytes` по умолчанию 8 MiB, максимум 64 MiB;
  timeout положительный, максимум 5 минут. tmpfs ограничен bytes и 8192 inodes;
  нехватка места даёт ошибку, даже когда логический размер файлов укладывается.

Ошибки входа, доверия, checksum и неподдерживаемые условия проверяются до
изменения mount namespace. Проверки возможностей, которые требуют реального
syscall (например, remount RO), завершаются ошибкой с обязательным cleanup.
Нет автоматической настройки systemd unit или системной конфигурации.

## Проверяемый launch contract systemd

`systemctl show` отражает загруженные настройки manager, а не автоматически
перечитанный текст unit. `daemon-reload` обновляет эти настройки; работающий
старый MainPID при этом может продолжать использовать прежнее окружение.
`NeedDaemonReload=yes` означает несогласованность файлов и loaded state, но
`no` не является номером поколения контракта или доказательством неизменности
внешних источников. В частности, изменение содержимого EnvironmentFile не
меняет загруженный список EnvironmentFiles и не требует daemon-reload.

Компонент дополнительно читает типизированные D-Bus properties через прямое
соединение `/run/systemd/private`, проверяя SO_PEERCRED root/PID1. Адрес из
`DBUS_SYSTEM_BUS_ADDRESS` не используется. Контракт сравнивается перед restart,
после его запроса, во время ожидания и при окончательном подтверждении:

| Группа | Закреплённые значения |
| --- | --- |
| Команды | `ExecConditionEx`, `ExecStartPreEx`, `ExecStartEx`, `ExecStartPostEx`, `ExecReloadEx`, `ExecStopEx`, `ExecStopPostEx`: path, **массив argv с сохранёнными границами**, flags |
| Окружение | `Environment`, `EnvironmentFiles`, `PassEnvironment`, `UnsetEnvironment`, текущий `Manager.Environment` |
| Источники unit | `FragmentPath`, `SourcePath`, `DropInPaths`, `NeedDaemonReload`, `Transient`, `TriggeredBy`; identity/metadata/SHA-256 fragment и всех загруженных drop-in |
| Identity/lifecycle | `User`, `Group`, `SupplementaryGroups`, `DynamicUser`, `PAMName`, `PIDFile`, `Restart`, `ExitType`, `RemainAfterExit`, `FileDescriptorStoreMax`, `NFileDescriptorStore` |
| Пути/namespace | `WorkingDirectory`, `UMask`, `ExecSearchPath`, `ExecPaths`, `NoExecPaths`, `RootDirectory`, `RootImage`, `RootHash`, `RootHashPath`, `RootHashSignature`, `RootImageOptions`, `PrivateUsers`, `PrivateNetwork`, `PrivateIPC`, `NetworkNamespacePath`, `IPCNamespacePath`, `MountAPIVFS`, `ProtectProc`, `ProcSubset`, `ExtensionDirectories`, `ExtensionImages` |
| Источники и stdio | `RuntimeDirectory`, `StateDirectory`, `CacheDirectory`, `LogsDirectory`, `ConfigurationDirectory`, `StandardInput`, `StandardOutput`, `StandardError`, `LogNamespace`, `LoadCredential`, `LoadCredentialEncrypted`, `SetCredential`, `SetCredentialEncrypted`; `ImportCredential` закрепляется, когда предоставлен manager |

Сохраняются и прежние проверки mount sandbox: `PrivateMounts`, `PrivateTmp`,
`PrivateDevices`, `ProtectClock`, `ProtectKernelTunables`, `ProtectKernelModules`,
`ProtectKernelLogs`, `ProtectControlGroups`, `ProtectHome`, `ProtectSystem`,
`ProtectHostname`, `ReadWritePaths`, `ReadOnlyPaths`, `InaccessiblePaths`,
`MountFlags`, `BindPaths`, `BindReadOnlyPaths`, `TemporaryFileSystem`.

Из Exec*Ex исключаются PID, exit status и execution timestamps: они закономерно
меняются при restart и не задают команду. Текстовый вывод ExecStart не парсится:
он объединяет argv пробелами и не сохраняет все необходимые границы аргументов.
Изменение флагов команд также считается изменением контракта. Весь типизированный
контракт хранится в памяти; диагностика содержит имя изменённого свойства,
без вывода environment/credential values.

Первоначально неподдерживаемы: отсутствующие обязательные properties/неизвестная
схема Exec*Ex, transient/generated units, `NeedDaemonReload=yes`, не root-controlled
fragment/drop-in, symlink в путях файлов unit (кроме точного usr-merge ниже), более 64 drop-in/1 MiB суммарного
текста, отличный от одного ExecStart, непокрытые environment files и credentials,
PAM environment, dynamic user, альтернативные user/network/IPC/mount namespace,
namespace extensions и log namespace, activation triggers, retained FD store,
PIDFile, ExitType не main, RemainAfterExit. Stdin поддерживается только null;
stdout/stderr — null, journal, inherit, kmsg. Сохраняются прежние запреты sandbox.
Постоянные `Environment`, `PassEnvironment`, `UnsetEnvironment`, WorkingDirectory,
статические user/group, допустимые команды и drop-in поддерживаются с точным
сравнением. Runtime-показатели команд не должны вызывать ложный отказ.

Начальная ошибка даёт `UnsupportedConfiguration`; изменение закреплённого
контракта после preflight — `InterferenceDetected`, в том числе изменение пути,
порядка, optional flag или числа повторений EnvironmentFiles. Новый непокрытый
input не расширяет snapshot. Автоматических daemon-reload/retry/fallback нет.

### EnvironmentFile v1: exact request coverage

Загруженное D-Bus свойство `EnvironmentFiles` обязано иметь сигнатуру `a(sb)`:
упорядоченный массив пар absolute path / optional boolean. Classifier требует
**отдельный явный `ControlledPathKind::File` target с эталонным SHA-256** для
каждого элемента. Вхождение только в directory manifest не считается покрытием.
Один target может обслуживать несколько одинаковых записей; исходный launch
contract сохраняет все дубликаты, порядок и flags без сортировки/дедупликации.
Без контекста request validator по-прежнему запрещает непустой EnvironmentFiles.

Поддерживается optional-present (`EnvironmentFile=-/absolute/file`), но не
optional-absent. Требуются существующий regular file, нормализованный literal
absolute path без symlink на любом уровне, wildcard/glob, неразрешённых `%`
specifiers и неоднозначных компонентов. Запрещены special permission bits,
xattrs/ACL/security labels, foreign/nested mounts и shared publication parents
по прежним правилам snapshots. Отсутствующий, непокрытый или неподтверждённый
EnvironmentFile даёт `UnsupportedConfiguration` до первого собственного mount.
Эталон и доверенность всех targets проверяются до создания tmpfs; envfile
повторно проверяется по SHA перед bind, identity CAS остаётся прежним.
Обычные config target checksum failures сохраняют прежние статусы.

Envfiles используют тот же ограниченный tmpfs, metadata/RO/bind/observer/deadline
и reverse cleanup lifecycle; второго publisher и преобразований содержимого нет.
Placeholder и private boundaries автоматически не создаются. Дополнительный
parent envfile (`/etc/default` или `/etc/sysconfig`) должен проходить тот же
propagation preflight, что и config parents/workspace.

В исследованных systemd252/255/257/258/259 PID1 читает bytes в своём namespace
перед каждым spawn Condition/Pre/Main/Post, передавая parsed values executor.
Поэтому все inputs публикуются **до restart** и остаются защищены до завершения
restart job (включая применимый StartPost), нового InvocationID/MainPID,
подтверждённого READY и финальных проверок. Cleanup выполняется и при ошибке;
его неудача никогда не Success. Содержимое envfiles и их values не логируются.
См. [исследование и exact source map](verified-config-environment-file-research.md).

Гарантия байтов EnvironmentFile не означает семантическую безопасность env/argv.
Выбор реального config path, Include closure и прочтение конфигурации **до READY**
остаются доверенной семантикой службы/caller. Generic activator не получает
аттестацию actual config read от произвольной службы. Native fixture отдельно
сообщает synthetic env/argv и mount ID/SHA реального read FD, но это не расширяет
публичный API и не является доказательством для неизвестного SSH binary.

Проверки последовательны, без атомарного «restart только при данном поколении».
Незаметный ABA свойств/источников со стороны привилегированного процесса не
исключён. Бинарный код службы, библиотеки, NSS и произвольные внешние данные её
логики не превращаются в проверенный снимок launch contract. Доверие к коду и
notify-семантике службы, а также полнота request остаются обязанностью вызывающего
кода. Новые свойства будущих systemd требуют отдельного анализа; проверка известных
полей не является обещанием покрыть любой будущий способ запуска.

## Propagation и подготовленные границы

Компонент **не создаёт постоянные private mount-границы**, не меняет propagation
`/`, `/etc`, `/run` или других существующих mount, не меняет systemd units и
не переводит службу в другой namespace. Подготовка подходящих границ на реальном
хосте — **будущая задача развёртывания**, не функция активатора.

Перед первым собственным mount определяется effective mount родителя каждой
цели через descriptor/statx mount ID и mountinfo. Аналогично проверяется будущий
каталог tmpfs в runtime workspace (по ближайшему существующему предку, если
каталоги ещё не созданы). Допустимы private/unbindable и non-shared slave parents;
shared, shared-slave и неизвестная propagation metadata дают
`UnsupportedConfiguration` до первого изменения mount namespace. Перед каждым
mount проверка повторяется, а финальный RO proof также отвергает shared mount.

Граница нужна **на родительском каталоге**, не на самом конфигурационном файле
или контролируемом каталоге. Уже существующий mount на самой цели по-прежнему
отвергается. Поэтому обычный AtomicFileWriter с созданием temporary sibling и
rename файла внутри подготовленного parent продолжает работать до/после активации.
Native-тест также выполняет atomic rename неконтролируемого sibling во время
активации. Защищённые объекты остаются временно перекрыты RO-снимком по основному
контракту.

Shared `/` совместим с компонентом при наличии ниже него необходимых подготовленных
non-shared границ для всех publication parents, включая runtime workspace.
Одна private-граница только вокруг `/run/fic` не изолирует bind в shared `/etc`.
Non-shared slave не передаёт наши mount наружу, но может получить событие upstream;
обнаруженное событие по-прежнему означает отказ активации.

Detached mount сам по себе не решает публикацию под shared parent. Проверка
`open_tree(OPEN_TREE_CLONE)` и `fsmount` с предварительным `mount_setattr(MS_PRIVATE)`
показала: присоединение через `move_mount` распространяется по shared destination.
Поздний MS_PRIVATE не отменяет первоначального появления mount в peers.
Новый Mount API в production не добавлен: он не устраняет данную проблему.

Topology должна сохраняться администратором на время операции. Последняя проверка
parent и последующий mount не атомарны; против CAP_SYS_ADMIN, меняющего topology
между ними, гарантии отсутствия propagation нет. Обнаруженный позднее отказ не
следует трактовать как доказательство отсутствия первоначальных peer-эффектов.
Безопасность этой версии относится к проверенной стабильной подготовленной
топологии, не к произвольному привилегированному противнику.

## Жизненный цикл

1. Проверить request, привилегии, пути, точный manifest и возможности readiness.
   Найденные mount с source `fic-vcsa.*` означают `ResidualMounts`: чужое или
   оставшееся состояние не присваивается и не размонтируется автоматически.
2. В `/run/fic/verified-config-activator` (production runtime path) взять
   неблокирующий FIC flock. Каталог имеет mode 0700, lock — root-owned закрытый
   обычный файл. Создать случайный приватный каталог операции и bounded tmpfs.
3. Прочитать и скопировать дерево через pinned descriptors/O_NOFOLLOW.
   Переиспользуются `ContentDigest`, `FileStats`; постоянные файлы не записываются,
   поэтому `AtomicFileWriter` здесь не нужен. Повторно проверить manifest.
4. Закрыть writable descriptors; сделать **superblock** tmpfs read-only через
   `MS_REMOUNT|MS_RDONLY`. Проверить mount RO и superblock RO, source/ID/object,
   содержимое и отказ writable open/create с `EROFS`. Закрепить атрибуты всего
   снимка, включая inode, size, ownership, permissions, mtime и ctime.
5. Через descriptor-based bind опубликовать каждый файл или **целый каталог**.
   Повторно доказать identity/RO/manifest. Корень tmpfs остаётся private.
6. После собственных mount открыть `/proc/self/mountinfo`. Начальный полный
   контроль опубликованных объектов выполняется уже при включённом observer;
   restart до этого не выполняется. Контрольный интервал начинается открытием
   observer, а не первой операцией mount: завершённые ABA до подписки не видны.
7. Проверенным `VerifiedProcessExecutor` выполнить `systemctl --no-block
   --job-mode=fail restart -- UNIT` без shell. Lifecycle properties читаются тем же
   проверенным executor; launch properties дополнительно читаются типизированным
   D-Bus через проверенный PID1 peer. Ожидание и объём чтения ограничены.
8. Ожидать новый InvocationID, `active/running`, отсутствие Job, стабильный
   MainPID/starttime/root/namespace; повторно подтвердить readiness и неизменные
   проверяемые свойства unit. Параллельно проверять sticky observer и deadline.
9. Повторить проверку всего снимка, целевых mount, RO, manifest, атрибутов и
   readiness; проверить observer ещё раз. Зафиксировать основной результат.
10. Снять только доказанно свои mount в обратном порядке обычным `umount`,
    проверить их отсутствие, удалить каталог операции. FIC lock остаётся.

`READY=1` — заявление службы о завершении инициализации, **не самостоятельное
доказательство чтения эталонной конфигурации**. Интерпретация `Success` опирается
на совокупность проверенного RO-снимка, отсутствия обнаруженного вмешательства,
проверок identity и доверия к корректной notify-семантике службы. Для simple/exec
такой договорённости нет, поэтому они отвергаются. Fixture native-тестов
действительно читает файлы до отправки READY, передавая digest и mount IDs
фактически открытых FD тесту; ожидаемые IDs фиксируются после публикации.

## Наблюдение и модель угроз

`poll(mountinfo)` не сравнивает только конечную таблицу. Observer сохраняет
sticky latch после первого `POLLPRI/POLLERR`, включая промежуточный poll:
Linux обновляет event cursor при poll, поэтому забывать уже увиденный event
нельзя. Любое обнаруженное изменение namespace в интервале означает неуспех,
даже если оно относится к постороннему пути либо конечный mount снова прежний.
Это может давать безопасные отказы при посторонней административной активности.

На проверенном WSL kernel `6.6.87.2-microsoft-standard-WSL2` установлено:

| Вмешательство во время инициализации fixture | Результат |
| --- | --- |
| Bind поверх цели и umount обратно (ABA), тот же namespace | Event, `InterferenceDetected` |
| Superblock `ro→rw→ro`, тот же namespace | Event, `InterferenceDetected` |
| `mount_setattr` RO→RW→RO, тот же namespace | Event, `InterferenceDetected` |
| Superblock remount из другого private mount namespace | **Event отсутствует**, чистый RO flip может завершиться `Success` |
| `fspick` + `fsconfig(FSCONFIG_CMD_RECONFIGURE)` из другого namespace | **Event отсутствует**, чистый RO flip может завершиться `Success` |
| Два предыдущих способа с записью evil, фактическим чтением службой и восстановлением байтов | Event отсутствует, но pinned ctime/mtime дают `InterferenceDetected` |

Последняя проверка усиливает обнаружение реальной записи, но **не превращает
poll или ctime в универсальную защиту от CAP_SYS_ADMIN**. Сторонний namespace,
другой API/kernel или привилегированная подмена могут иметь иную семантику.
Нельзя гарантировать обнаружение каждого transient remount или любого
вмешательства привилегированного процесса. Итоговые последовательные проверки
не атомарны; операция не предоставляет линейризуемого доказательства против
такого противника. LSM/eBPF/auditd и постоянный мониторинг не добавлены.

Источник/ID/device/inode/attrs проверяются перед cleanup. Чужой overmount не
снимается. Linux не предоставляет атомарного «umount только при ожидаемом mount
ID»: между проверкой и обычным `umount` остаётся **явно принятая остаточная гонка
с CAP_SYS_ADMIN**. ID может переиспользоваться; ID без остальных проверок и
observer не рассматривается как полное доказательство identity.

## Частичные отказы, timeout и crash

При ошибке всегда предпринимается reverse cleanup всех записанных собственных
mount. `MNT_DETACH` не используется. `EBUSY`, подмена или непроверенная identity
сохраняются в `cleanupErrors`/`residualPaths`; основной статус не теряется.
Неудача одного release не мешает попыткам остальных. Никакого rollback
постоянной конфигурации или восстановления предыдущего процесса нет.

Deadline ограничивает ожидание readiness и subprocesses; это не realtime
верхняя граница блокирующих kernel/filesystem calls. Cleanup выполняется и после
deadline. Если удалось запомнить pending Job, при неуспехе предпринимается
ограниченная отмена именно этого Job. Она не гарантирует остановку службы:
при timeout/error и после снятия bind служба может продолжить инициализацию.
Активатор тогда **не сообщает Success** и не делает неоговорённый `stop`.
Вызывающий код обязан разбирать ошибку и решать дальнейшее действие.

RAII не исполняется при SIGKILL/аварии. Временные mount могут остаться и закрывать
оригиналы. Следующий вызов обнаруживает source `fic-vcsa.*` и отказывает, сохраняя
пути для ручной проверки. Автоматического startup recovery/adoption нет.
Администратору следует проверить namespace, mountinfo, mount ID/source и
занятые descriptors перед ручным освобождением. Source marker сам по себе не
является доверенным правом на unmount; mount в других namespaces не перечисляются.

## Проверки и воспроизведение

Обычный CTest содержит `verified_config_service_tests` и native entrypoint.
Без явного `FIC_ACTIVATOR_NATIVE=1`, root/CAP_SYS_ADMIN, контейнера и systemd PID1
native entrypoint честно возвращает SKIP (77), не меняя системные пути.
Test hooks доступны только при `FIC_ACTIVATOR_TESTING`; production их не содержит.
Fault injection применяется только к ошибкам syscall; положительные mount,
EROFS, restart, readiness, races и cleanup проверяются настоящим Linux/systemd.

`tests/integration/verified_config_service/run-native.sh IMAGE PLATFORM`
строит actual компонент + fic-core/platform, запускает disposable Docker с
private mount/cgroup namespaces и fixture `fic-vcsa-test.service`. Docker явно
согласован вместо Podman. Требуются готовые образы с компилятором, systemd и
libsystemd-devel (рецепты `Containerfile.deb`/`Containerfile.alt`); BASE_IMAGE
можно переопределить. Не монтировать host `/etc`, `/run`, `/sys/fs/cgroup` или
Docker socket в привилегированный контейнер. Полный проект и обычный CTest
проверяются отдельно в непривилегированном build-контейнере.

Native harness использует SOCK_SEQPACKET barriers «до чтения / прочитано / READY»,
а не случайные sleep для гонок. Сценарии покрывают одиночный файл, каталог,
совместный контроль, metadata, неверный SHA, missing/extra/symlink/overlap/nested
mount, tmpfs/RO/bind errors, EROFS, реальный notify restart/failure/timeout,
простую/неактивную службу, вмешательства из таблицы, sticky poll, EBUSY,
совместные primary/cleanup errors, чужой overmount, повторный вызов и SIGKILL.
После штатного успеха/ошибок проверяются отсутствие остаточных mount и прежние
байты постоянных fixture-файлов. Foreign/crash остатки освобождает только
отдельная тестовая административная процедура внутри контейнера.

Окончательный usr-merge + EnvironmentFile native-прогон (2026-10-18), actual production
activator с test-only fault/barrier hooks:

| Userspace / systemd | Focused build | Native |
| --- | --- | --- |
| Debian 12 / 252.39 | PASS | 132 PASS, 0 FAIL, 0 SKIP |
| Debian 13 / 257.13 | PASS | 132 PASS, 0 FAIL, 0 SKIP |
| Ubuntu 24.04 / 255.4 | PASS | 132 PASS, 0 FAIL, 0 SKIP |
| Ubuntu 26.04 / 259.5 | PASS | 132 PASS, 0 FAIL, 0 SKIP |
| ALT p11 / 258.9-alt1 | PASS | 132 PASS, 0 FAIL, 0 SKIP |

Profiles: `debian-12`, `debian-13`, `ubuntu-24.04`, `ubuntu-26.04`, `alt-p11`.

Полные configure/build Debian12 на окончательных исходниках PASS; полный CTest:
**186 PASS, 0 FAIL, 1 ожидаемый native opt-in SKIP** (187 tests, 161.79 s).
`verified_config_service_tests` PASS; privileged native выполняется отдельно по
таблице, а не пропускается в общей validation. Full build/CTest запускались с
`QT_QPA_PLATFORM=offscreen`, `FIC_TARGET_PLATFORM=debian-12`, `-j6`, без сети и
host security mounts; log `build-verified-config/logs/full-debian12-usrmerge-final.log`.
Для Git static checks внутри disposable контейнера задан только
`safe.directory=/src`. В полном CTest сняты `DAC_OVERRIDE`/`DAC_READ_SEARCH`:
иначе контейнерный root обходит chmod-based permission faults MutationJournal.
Тот же неизменённый test binary без bypass проходит. Build volume должен быть
записываемым контейнерному UID без DAC bypass; это настройка тестовой среды,
не изменение необходимых privileges production activator/native mount suite.
Локальные runner logs: `build-verified-config/logs/*-usrmerge-public.log` (ignored artifacts).
Перед suite runner ждёт завершения boot jobs PID1: доступность socket сама по
себе ещё не исключает штатные boot mount events. Это readiness инфраструктуры,
не fallback вместо notify fixture. В промежуточных параллельных Ubuntu26 прогонах были безопасные отказы
observer на положительных сценариях. Источник конкретного постороннего mount
event не атрибутирован; ожидание boot jobs исключает один известный источник
фоновых изменений, но не делает namespace изолированным от любой активности
PID1. Финальная матрица прошла; production observer не ослаблялся.
Под нагрузкой также выявлен D-Bus ETIMEDOUT, ранее ошибочно переводившийся в
InterferenceDetected: теперь он сохраняет существующий статус TimedOut. Все пять строк используют одно ядро
`6.6.87.2-microsoft-standard-WSL2`, не пять независимых distro kernels.

EnvironmentFile regressions дополнительно проверяют:

* actual env/argv и SHA/mount ID config FD, новый MainPID/InvocationID/READY;
  optional-present, несколько files с override, повторы одного target,
  config directory + отдельный envfile, ExecCondition/StartPre/StartPost;
* отсутствие покрытия, directory-only, mandatory/optional absence, symlink/
  dangling symlink, glob, directory/FIFO, wrong SHA, special bits/xattr,
  shared parent и чужой mount — UnsupportedConfiguration **без mount syscall**;
* missing/wrong `a(sb)` schema, malformed entries, relative/non-normalized и
  unresolved specifier paths — unit classifier negatives. Systemd может сам
  нормализовать/отбросить такие unit entries; raw-invalid schema не выдумывается
  в настоящем PID1. Проверяется именно полученный typed loaded contract;
* in-place/rename до bind — отказ; preopened original writer после публикации
  не меняет systemd env, foreign bytes сохраняются после cleanup; запись между
  main read и READY не меняет verified invocation, следующий restart видит её;
* daemon-reload меняет path/order/optional/duplicates или добавляет непокрытый
  input — InterferenceDetected; изменение до READY также отказ;
* sticky observer на env mount ABA, partial bind cleanup, startup failure,
  READY timeout, env EBUSY (CleanupFailed/primary Success), foreign cleanup mount,
  SIGKILL residual refusal без adoption; все прежние topology/cross-namespace
  negatives сохранены и повторены.

В исходном наборе ACL/security label не испытывались как отдельные providers.
Новый bounded-xattr follow-up ниже добавляет настоящие POSIX ACL и file
capabilities; enforcing SELinux по-прежнему не проверен.
Содержимое envfiles не выводится; fixture сообщает только synthetic whitelist.

Hardening native-набор дополнительно проверяет shared parent и shared-slave
refusal без mount syscall, private/non-shared slave границы под shared ancestor,
неизменную таблицу mount отдельного peer namespace при подготовке tmpfs,
публикации, фактическом чтении и cleanup. Положительные file/directory/combined
сценарии требуют совпадения SHA и mount IDs; fixture удерживает реальные FD до
statx/read/hash, закрывая их до READY. Негативный случай читает заранее открытые
исходные FD с теми же байтами: проверка аттестации отвергает их mount IDs. Это
проверка harness, а не новый production API или требование к обычным службам.

Регрессии launch contract используют настоящие unit/drop-in, daemon-reload и
IPC «до чтения / до READY». После отказа изменённый unit действительно запускается
отдельной тестовой командой и читает alternate config. Проверены ExecStart,
Environment, добавление drop-in, изменение перед READY, NeedDaemonReload=yes,
EnvironmentFile/content и manager Environment при постоянном PassEnvironment.
Отдельная negative-проверка удаляет обязательные поля из реально полученного
контракта; она не заменяет реальные systemd сценарии.

Нативная загрузка отдельной Linux ВМ/физического хоста пока не проверялась.
Shared topology воспроизведена настоящими mounts внутри контейнера, а не принята
на веру из стандартной Docker topology. Все пять строк используют один WSL
kernel, поэтому не доказывают одинаковую семантику всех distro kernels.

## Security review EnvironmentFile support

* Uncovered input не допускается: typed `a(sb)` + точное совпадение явного File
  target и lowercase reference SHA; без request context непустой список запрещён.
* Порядок/flags/дубликаты сохранены в исходной canonical typed property и
  сравниваются перед/после restart, при READY и final confirmation.
* Snapshot полностью опубликован до единственного restart; при partial failure
  restart не вызывается. Законченный restart job включает StartPost; защита
  снимается после final proof либо по failure path с отдельным cleanup status.
* Новый classifier не подменяет проверки metadata/trust/CAS/propagation. Для
  envfile есть дополнительный pre-bind SHA recheck. Окно check→bind и
  check→umount остаётся в прежней документированной модели; атомарного kernel
  условного bind/umount не появилось. Original FD write после публикации не
  меняет отдельный immutable snapshot.
* Ни политика, ни ownership/journal/rollback, trust enrollment, unit lifecycle
  или systemd socket activation не изменены; публичные API/статусы прежние.
* Это не обещание защиты от произвольного CAP_SYS_ADMIN, launch-contract ABA,
  модификации памяти, неизвестных inputs/бинарного кода или позднего reread.
  Сохранены measured alternate-namespace observer blind spots из таблицы выше.
* Гарантия bytes не проверяет смысл `SSHD_OPTS=-f/-o` и Include closure. Реальный
  SSH adapter не добавлен. Debian12 usr-merge unit provenance поддерживается
  по узкому контракту ниже; Ubuntu socket activation и ALT отсутствие notify
  остаются отдельными препятствиями.

## Trusted usr-merge для unit source

Исключение действует только при чтении `FragmentPath`/`DropInPaths`, начинающихся
с `/lib/systemd/system/`. Единственный разрешённый symlink — root-owned `/lib`
с **точным** target `usr/lib` или `/usr/lib`. Наличие usr-merge доказывается по
файловой системе, без доверия к os-release. Настоящий каталог `/lib` также допустим.
Обычные `/usr/lib/systemd/system` и `/etc/systemd/system` не требуют исключения.
Другие symlink, включая `/usr`, вложенные каталоги, каталог drop-ins и конечный
файл, запрещены. `/lib/other` не получает это разрешение. Права symlink 0777
не трактуются как writable regular file: проверяются тип, UID, родитель и target.

Внутренний reader начинает обход с закреплённого descriptor `/`; каждый компонент
открывается `openat(O_NOFOLLOW)`, каталоги — `O_PATH|O_DIRECTORY`, alias —
`O_PATH|O_NOFOLLOW`. Target читается `readlinkat(aliasFd, "", ...)`, без повторного
разрешения имени ссылки. После точного whitelist target конечный путь строится
как `/usr/lib/systemd/system/...` и открывается тем же no-follow обходом от того
же root descriptor. Ни canonical()/realpath(), ни обычного follow-symlink нет.
Root и все каталоги требуют UID0 и отсутствия group/world write; конечный объект —
root-controlled regular file. `statx(STATX_MNT_ID)` обязателен, иначе отказ.

Fingerprint содержит исходный путь PID1, подтверждённый канонический путь,
последовательность identity root/каталогов/alias/файла (mount ID, dev, inode,
UID/GID/mode), target и mtime/ctime alias, прежние metadata конечного файла
(включая размер, mtime/ctime) и SHA-256 содержимого. Directory timestamps
намеренно не закрепляются: создание соседнего файла не меняет данный путь.
Descriptors компонентов удерживаются до конца capture; после bounded read
повторный обход от root должен дать ту же цепочку и тот же конечный объект.
Metadata конечного FD проверяются до чтения, после чтения и после повторного
обхода. Суммарный прежний budget 1 MiB и ≤64 drop-in сохранены; путь ограничен
4096 bytes и 128 компонентами. Public API не изменён.

Неподдерживаемая начальная топология даёт `UnsupportedConfiguration`.
Обнаруженная смена цепочки во время capture — `InterferenceDetected`;
существующий SystemdActivation повторяет весь launch contract до restart,
после постановки restart, на READY и перед commit. Поэтому новая inode ссылки
с прежним target или файла с прежним SHA также меняет контракт. Это не обещание
непрерывного наблюдения unit tree: скрытый privileged ABA между проверками и
изменения после последней проверки остаются за границей гарантии. Удержание FD
не запрещает CAP_SYS_ADMIN менять namespace/дерево и не превращает check в CAS.

### Security review usr-merge

* Произвольный root-owned symlink с корректным SHA не принимается; target alias
  не может вывести обход в `/tmp`, `/etc`, `/run` или вне vendor tree.
* Подмена alias между инспекцией и открытием не перенаправляет reader: он открывает
  только точный canonical path от root FD, а повторный обход проверяет alias.
* Замены alias/каталогов/конечного файла обнаруживаются по identity и metadata,
  даже если SHA прежний; изменение bytes дополнительно обнаруживается SHA.
* SHA не заменяет provenance и не доказывает семантику конфигурации. READY,
  mount namespace, propagation, source coverage и cleanup условия Success прежние.
* `openAbsolute()`, EnvironmentFile/контролируемые файлы/snapshots остаются строго
  no-symlink; SSH-политики, ownership, apply/rollback и MutationJournal не затронуты.
* Ограничения budget, fail-closed и timeout контракта сохранены; hook подмен
  существует только при `FIC_ACTIVATOR_TESTING`, production не вызывает hooks.

### Native acceptance usr-merge

Debian12 stock `readLaunchContract("ssh.service")` принял настоящий
`FragmentPath=/lib/systemd/system/ssh.service`; повторное чтение идентично.
Fingerprint содержит `/lib` identity/target и canonical
`/usr/lib/systemd/system/ssh.service`. `validateLaunchContract` без request context
по-прежнему отказывает из-за EnvironmentFile coverage — provenance blocker снят,
полная совместимость SSH этим не утверждается. Debian13/Ubuntu/ALT stock reader
проверен по реальным `/usr/lib/systemd/system` paths; Ubuntu отдельно отказывает
по triggers, Debian13/ALT — по EnvironmentFiles без coverage.

Собственная vendor notify fixture Debian12 действительно получила FragmentPath
`/lib/systemd/system/fic-vcsa-test.service`; остальные четыре — `/usr/lib/...`.
Прямой публичный `VerifiedConfigServiceActivator::activate()` проверен до Success,
с assertions нового InvocationID, READY, отсутствия cleanup errors/residual mounts
и сохранения исходной конфигурации. Same-SHA rename unit после preflight даёт
InterferenceDetected. Существующие обычные `/etc` units/drop-ins и весь прежний
91-case набор проверяются далее в том же gate без ослабления assertions.

Новые filesystem cases проверяют оба target представления alias, stable digest,
обычные paths и vendor drop-ins; final/intermediate/drop-in/extra-usr symlinks,
loop/escape/unexpected targets, owner/mode/type/depth/size/identity отказ;
управляемые подмены alias/каталога/файла и in-place write; same-SHA replacement,
повторный content fingerprint и общий 1 MiB budget. Никаких случайных sleep для
подмен нет: callback стоит между закреплением FD/metadata и чтением.

Filesystem unit-source тесты выполняются внутри native gate над отдельным
root descriptor в `/etc/fic-vcsa-tests/unit-root`, с теми же trust checks.
Они не меняют `/lib` systemd-контейнера. Stock SSH probe только удерживает unit
загруженной через system-bus RefUnit и читает её production reader через прямое
root-PID1 соединение; он не запускает и не перезапускает SSH.

## Первичные источники

* [mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html): mount RO и superblock RO.
* [umount(2)](https://man7.org/linux/man-pages/man2/umount.2.html): обычный release и EBUSY.
* [mountinfo](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html),
  [statx](https://man7.org/linux/man-pages/man2/statx.2.html),
  [mount namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html).
* [poll(2)](https://man7.org/linux/man-pages/man2/poll.2.html) и
  [Linux mounts_poll implementation](https://github.com/torvalds/linux/blob/v6.12/fs/proc_namespace.c): event cursor.
* [mount_setattr](https://man7.org/linux/man-pages/man2/mount_setattr.2.html),
  [fsconfig](https://man7.org/linux/man-pages/man2/fsconfig.2.html),
  [kernel mount API](https://docs.kernel.org/filesystems/mount_api.html).
* [systemd service contract (v252)](https://github.com/systemd/systemd/blob/v252/man/systemd.service.xml):
  notify readiness, simple/exec и startup timeout. Собственный deadline активатора
  не продлевается `EXTEND_TIMEOUT_USEC` службы.

* [Linux shared subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html),
  [attach_recursive_mnt / do_move_mount](https://github.com/torvalds/linux/blob/v6.6/fs/namespace.c):
  распространение определяется destination topology.
* [systemd D-Bus contract](https://github.com/systemd/systemd/blob/v252/man/org.freedesktop.systemd1.xml),
  [Exec*Ex implementation](https://github.com/systemd/systemd/blob/v252/src/core/dbus-service.c),
  [execution properties](https://github.com/systemd/systemd/blob/v252/src/core/dbus-execute.c),
  [environment semantics](https://github.com/systemd/systemd/blob/v252/man/systemd.exec.xml).

## Bounded xattr validation (follow-up к `692d34a`)

### API и OverlayFS

Проверка работает с закреплённым FD и делает один `flistxattr` с настоящим
буфером `XATTR_LIST_MAX` (65536 байт) до чтения объекта и ещё один после чтения.
Размер не берётся из файловой системы; повторов, чтения значений, фильтра имён
и удаления атрибутов нет. Буфер локален одному перечислению и освобождается
до рекурсивного обхода дочерних объектов; глубина обхода по-прежнему ограничена.
Нулевая длина результата принимается только вместе с проверками контекста и
метаданных. Любой положительный размер отклоняется, даже если value пуст.
Невозможный размер больше буфера и **все** ошибки означают отказ, включая
`ERANGE`, `E2BIG`, `EINTR`, `ENOMEM`, `ENOTSUP`/`EOPNOTSUPP`, `EPERM`, `EACCES`.
Прежнее исключение для `ENOTSUP` удалено. Имена и значения не попадают в
production-диагностику.

Причина прежнего false positive — не изменение файла между двумя вызовами.
В `ovl_listxattr` ветка `size == 0` возвращает размер underlying list до
фильтрации внутренних OverlayFS metadata; с буфером kernel выполняет фильтрацию
и может вернуть 0. Такой порядок есть и в
[WSL 6.6.87.2](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.87.2/fs/overlayfs/inode.c#L401),
и в [upstream Linux 6.6](https://github.com/torvalds/linux/blob/v6.6/fs/overlayfs/inode.c#L390).
FIC не распознаёт и не пропускает `trusted.overlay.*`: решение принимает
фактический результат kernel API. Size-query в production больше не вызывается.

Семантика [listxattr(2)](https://man7.org/linux/man-pages/man2/listxattr.2.html):
возвращаются доступные вызывающему имена, а не доказательство отсутствия любой
скрытой metadata. В Linux список ограничен 64 KiB; переполнение может давать
`E2BIG`. [getxattr(2)](https://man7.org/linux/man-pages/man2/getxattr.2.html)
читает значение конкретного имени: нулевая длина value не означает отсутствия
имени, а перебор известных имён не доказывает отсутствия остальных. Поэтому
такой fallback здесь не используется.

### Полномочия, filesystem и LSM

Перед каждым перечислением требуются euid 0 и эффективный `CAP_SYS_ADMIN`
текущего **thread в initial user namespace**. Проверяются capget, namespace FD
`/proc/thread-self/ns/user`, nsfs magic, `NS_GET_NSTYPE` и зарезервированный
initial inode `0xEFFFFFFD`. Число определено в
[Linux 6.6 proc_ns.h](https://github.com/torvalds/linux/blob/v6.6/include/linux/proc_ns.h#L37),
в новых UAPI headers — `USER_NS_INIT_INO`. Неизвестный kernel contract даёт
отказ. UID 0, UID map и capabilities внутри дочернего user namespace сами по
себе недостаточны. Проверки не кэшируются между объектами/перечислениями.

По [xattr(7)](https://man7.org/linux/man-pages/man7/xattr.7.html), `user.*`
подчинены обычным правам, `trusted.*` требуют `CAP_SYS_ADMIN`, `system.*`
определены filesystem, `security.*` — security module. В частности,
`ovl_can_list` скрывает trusted names без capabilities в initial namespace.
[VFS Linux](https://github.com/torvalds/linux/blob/v6.6/fs/xattr.c#L452)
проверяет LSM list permission; ошибка не принимается за отсутствие.
Универсального syscall «докажи отсутствие metadata, которую provider скрывает»
нет. Успешный пустой список — свидетельство только в рамках доверенного
kernel/filesystem/LSM и указанного контекста; произвольный FUSE/provider,
намеренно скрывающий metadata, не входит в поддерживаемую модель. Недостаточные
полномочия и обнаруженные ошибки проверки контекста/listing дают
`UnsupportedConfiguration`, а не permissive fallback. Это не аттестация
произвольного стороннего filesystem или отсутствия всех LSM effects.

POSIX access/default ACL на проверенных OverlayFS/tmpfs перечисляются как
`system.posix_acl_*`; nontrivial ACL отвергаются. ext4 хранит xattrs/ACL в своих
inode/block structures, tmpfs — в памяти, OverlayFS делегирует и фильтрует
underlying list: их storage и ограничения различаются. Совпадение API не
заменяет native gate конкретного provider. Поддержка ACL/security labels в
snapshot **не добавлена**; существующий запрет enforcing SELinux сохранён.

### TOCTOU и security review

* Уже присутствующая metadata выявляется в preflight до первого собственного
  mount: `UnsupportedConfiguration`. Новое непустое перечисление после чтения
  даёт `InterferenceDetected`; ошибка перечисления всё равно fail-closed.
* Обе проверки используют тот же FD, без повторного разрешения pathname.
  Сравнения inode/device/size/mode/UID/GID/mtime/ctime и mount ID сохранены;
  изменения с пустым итоговым списком выявляет прежний `ChecksumMismatch`.
  Последующая source CAS и проверки publication не менялись.
* Перечисления и stat не атомарны. Добавление/удаление между проверками без
  наблюдаемого изменения метаданных, coarse-clock ABA и privileged восстановление
  состояния не гарантированно обнаруживаются. Две проверки не означают полной
  защиты от произвольного привилегированного writer. Детерминированные transient
  тесты ждут отдельной ctime-секунды с учётом coarse clock, а не обещают такую
  гарантию для любых реальных гонок.
* Непустой доступный список не может стать разрешённым из-за размера/value/имени;
  малый буфер, отказ доступа и неизвестная ошибка не превращаются в Success.
  Недоступный namespace не принимается за пустой trusted namespace.
* RO snapshot lifecycle, mount publication, observer, READY, cleanup и правила
  `CleanupFailed`/residual mounts не изменены. Отказ при неудачной очистке остаётся
  обязательным; xattr validation не создаёт нового пути успешного завершения.

Результаты native regression, реальные copy-up inputs OpenSSH и непроверенные
окружения: [follow-up отчёт](verified-config-openssh-native-validation.md#bounded-xattr-follow-up).

## Внутренний proof entrypoint

Для [SSH adapter v1](ssh-verified-activation-adapter.md) добавлен внутренний
`VerifiedConfigActivationProof.h`. `activateWithProof()` использует тот же
perform engine с expected launch/source identities/attributes, read-only
validator после публикации до restart и validator готового процесса. После
callbacks повторяются штатные snapshot/observer/readiness проверки; ошибки
проходят через тот же cleanup. Generic engine не получает SSH-specific знаний.
Публичный `activate()` и его API не изменены. Default path без proof сохраняет
предыдущие проверки; snapshot/restart/cleanup implementation не дублируется.
