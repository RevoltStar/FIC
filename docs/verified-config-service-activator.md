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
  root с эффективным `CAP_SYS_ADMIN` и правами чтения/копирования атрибутов.
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
fragment/drop-in, symlink в путях файлов unit, более 64 drop-in/1 MiB суммарного
текста, отличный от одного ExecStart, внешние environment files и credentials,
PAM environment, dynamic user, альтернативные user/network/IPC/mount namespace,
namespace extensions и log namespace, activation triggers, retained FD store,
PIDFile, ExitType не main, RemainAfterExit. Stdin поддерживается только null;
stdout/stderr — null, journal, inherit, kmsg. Сохраняются прежние запреты sandbox.
Постоянные `Environment`, `PassEnvironment`, `UnsetEnvironment`, WorkingDirectory,
статические user/group, допустимые команды и drop-in поддерживаются с точным
сравнением. Runtime-показатели команд не должны вызывать ложный отказ.

Начальная ошибка даёт `UnsupportedConfiguration`; изменение закреплённого
контракта после preflight — `InterferenceDetected`. EnvironmentFile намеренно
не поддерживается: отдельно проверить его hash до и после запуска недостаточно,
чтобы доказать, какие байты прочитал manager перед exec. Тест реально меняет
содержимое файла при прежних EnvironmentFiles/NeedDaemonReload и затем запускает
службу с другим config root. Поддержка таких источников требует отдельного
доказанного протокола закрепления входных данных.

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

Окончательный native-прогон (2026-10-17):

| Userspace / systemd | Сборка actual компонента | Native |
| --- | --- | --- |
| Debian 12 / 252.39 | PASS | 50 PASS, 0 SKIP |
| Debian 13 / 257.13 | PASS | 50 PASS, 0 SKIP |
| Ubuntu 24.04 / 255.4 | PASS | 50 PASS, 0 SKIP |
| ALT p11 / 258.9-alt1 | PASS | 50 PASS, 0 SKIP |

Дистрибутивы проверены platform profiles `debian-12`, `debian-13`,
`ubuntu-24.04`, `alt-p11`. Полная сборка Debian 12 PASS; полный CTest: 186 PASS, 1 ожидаемый native
opt-in SKIP, 0 FAIL. После окончательной per-file SHA/ID проверки fixture
полная сборка обновлена, связанные CTest повторно PASS (native opt-in SKIP).
Privileged native выполнен отдельно,
как показано в таблице. Матрица остальных строк относится к focused native build/runtime, а не полной
сборке GUI/пакетов. Build/runner logs этой сессии:
`/tmp/fic-hardening-{d12,d13,u24,alt}.log`,
`/tmp/fic-hardening-full-d12.log`, `/tmp/fic-hardening-final-targets.log`
(временные внешние артефакты, не часть Git).
Все контейнеры используют один host kernel: четыре userspace не являются
проверкой четырёх разных kernels или загрузки настоящей ОС.

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
на веру из стандартной Docker topology. Все четыре строки используют один WSL
kernel, поэтому не доказывают одинаковую семантику всех distro kernels.

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
