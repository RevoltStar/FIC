# EnvironmentFile verified activation — architecture research / native PoC

Дата: 2026-10-17. База: `d0c7e2d642a15c6f7a126f8ec06f83df024ff71a`.
Изучены `1782cc6`, `7e91772`, `d0c7e2d`,
[контракт активатора](verified-config-service-activator.md) и
[предыдущий native audit](verified-config-native-compatibility-audit.md).
Это исследование и disposable fixture, **production не изменён**.

## 1. Результат и рекомендуемое решение

**Для существующих обычных EnvironmentFile временная RO-публикация в namespace
PID1 подходит как механизм защиты в принятой ограниченной модели угроз.**
Результат основан не на двух SHA, а на exact distro source path
`service_spawn → exec_spawn → exec_context_load_environment → load_env_file`,
прямом native наблюдении reader PID1 и проверке actual env/argv/config у нового
процесса с IPC barriers. Во всех пяти userspaces PID1 читает EnvironmentFile
**до** fork/spawn executor. Последующее чтение файла самим executor для этого
входа не требуется: ему передаются уже разобранные values.

Рекомендуется **B на механизме A**: отдельный внутренний launch-input contract,
проверяющий связь loaded ordered `EnvironmentFiles` с trusted request targets,
плюс существующий общий tmpfs/copy/RO/bind/observer/cleanup. Второй snapshot engine
и отдельный запуск службы не нужны. Первая production версия должна принимать
только существующие regular absolute literal inputs с полным expected SHA;
**отказывать optional-absence, wildcard, symlink и непокрытым inputs**. Флаг optional
может оставаться true, если файл присутствует и защищён во всём окне.

Это **не** доказанная production реализация: нынешний активатор продолжает
запрещать EnvironmentFiles. PoC не вызывает activate, не заменяет его preflight,
CAS/recovery/launch checks и не решает Ubuntu sockets или ALT simple readiness.
Ограничения против произвольного CAP_SYS_ADMIN, неизвестных новых systemd versions,
незаметного launch-contract ABA и известные observer blind spots сохраняются.

## 2. Среды и источники

Пять disposable Docker с настоящим systemd PID1. Все используют одно ядро
`6.6.87.2-microsoft-standard-WSL2`, а не пять distro kernels. Images
`fic-ssh-audit:{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}` подготовлены в
предыдущем аудите. Source и binary fixture собирались отдельно; runtime контейнеры
новые, network none, private cgroup namespace, собственные tmpfs `/run`/`/tmp`,
без host `/etc`, `/run`, cgroups или Docker socket. Старые subject контейнеры
после перезапуска среды отсутствовали; использованы сохранившиеся images.

| Native userspace | systemd package/source | Reader | Итог PoC |
|---|---|---|---|
| Debian12 | 252.39-1~deb12u2 | PID1, fork child | 33 PASS / 0 FAIL |
| Debian13 | 257.13-1~deb13u1 | PID1, serialized systemd-executor | 33 PASS / 0 FAIL |
| Ubuntu24.04 | 255.4-1ubuntu8.18 | PID1, serialized systemd-executor | 33 PASS / 0 FAIL |
| Ubuntu26.04 | 259.5-0ubuntu3.4 | PID1, serialized systemd-executor | 33 PASS / 0 FAIL |
| ALT p11 | 258.9-alt1 | PID1, serialized systemd-executor | 33 PASS / 0 FAIL |

Результаты: [evidence JSON](verified-config-environment-file-research-evidence.json).
Все значения искусственные; не собраны private keys, credentials или полный
system environment. Full VM недоступна (`/dev/kvm` отсутствует); предыдущая ALT-ВМ
не использована. VM/physical/kernel-specific results — `NOT_TESTED`.

Для Debian/Ubuntu получены exact sourceVersion через `dpkg-query` и
`apt-get source --download-only systemd=<version>`, затем `dpkg-source -x` с distro
patches. Для ALT exact SRPM распакован rpm2cpio/cpio, upstream tar +
`systemd-258.9.patch`, согласно `systemd.spec %prep` (`%setup`, `%patch1 -p1`).
Последующие spec sed затрагивают test shell paths, не исследованные core functions.
Источники — локальные research artifacts в ignored `build-environment-file-research`.
Проверка воспроизводимости binary из sources не проводилась; идентичность версии/
distro patch set не является reproducible-build attestation.

| Первичный source package | SHA256 metadata |
|---|---|
| [Debian252.39](https://deb.debian.org/debian/pool/main/s/systemd/systemd_252.39-1~deb12u2.dsc) | `f2f952ae61fd40f1ef3ee48c8721e23eaaec5396ef5f1b0c2e138d78fade9c6e` |
| [Debian257.13](https://deb.debian.org/debian/pool/main/s/systemd/systemd_257.13-1~deb13u1.dsc) | `1b3405d671a82d1e20c9d99f52d4336aafe8543b28d04e91b7f1f586d3a667c7` |
| [Ubuntu255.4](https://archive.ubuntu.com/ubuntu/pool/main/s/systemd/systemd_255.4-1ubuntu8.18.dsc) | `04154737afced0898fc7966b85e88505fb3a17f46c8c7079576d022cdeb67304` |
| [Ubuntu259.5](https://archive.ubuntu.com/ubuntu/pool/main/s/systemd/systemd_259.5-0ubuntu3.4.dsc) | `c4c764e0b98b7840619f16f42fb8229a344bc2946bd1a74612280d5e218f8177` |
| [ALT258.9 SRPM mirror](https://distrib-coffee.ipsl.jussieu.fr/pub/linux/altlinux/p11/branch/files/SRPMS/systemd-258.9-alt1.src.rpm) | `f958531245058b016a60dc1d6e8488aaf0a9bbf5fbf21334f836c1e870298dcc` |

Repositories могут ротировать files; зафиксированы exact filenames/hashes.
Versioned `man/systemd.exec.xml` прочитан **из каждого source package**;
внешние versioned man pages при проверке были недоступны. Выводы не основаны
на latest-only документации.

## 3. Кто, где и когда читает EnvironmentFile

### Source map — строки patched sources

Все пути ниже относительны root соответствующего source package.

| Версия | Unit parser: load-fragment.c | execute.c: exec_spawn / load call / loader / load_env_file | Передача в executor / merge / argv / exec |
|---|---|---|---|
| 252.39 | config_parse_unit_env_file :2708 | :5209 / :5253 / :5660 / :5697; fork :5288 | execute.c files_env → exec_child :5306; merge :4614–4619; argv :5153; exec :5188 |
| 257.13 | :2657 | :429 / :456 / :844 / :881 | execute-serialize.c :1429, :1709; exec-invoke.c merge :4897, argv :5621, exec :5670 |
| 255.4 | :2676 | :354 / :381 / :733 / :770 | execute-serialize.c :1398, :1648; exec-invoke.c :4501, :5177, :5219 |
| 259.5 | :2639 | :470 / :498 / :897 / :934 | execute-serialize.c :1239, :1509; exec-invoke.c :5711, :6410, :6475 |
| 258.9 ALT | :2666 | :464 / :492 / :892 / :929 | execute-serialize.c :1236, :1513; exec-invoke.c :5685, :6362, :6427 |

`src/core/service.c` service_spawn вызывает exec_spawn (например, Debian257 :1929).
Это код manager, не `systemd-executor`. Новые версии сериализуют parsed
`params->files_env` в invocation state перед posix_spawn_wrapper; executor
десериализует **values**, а не повторно открывает исходный envfile. В 252 values
унаследованы fork child. В обоих вариантах дальнейшие namespace/root/sandbox
changes целевого процесса не определяют, где PID1 первоначально прочёл envfile.

`src/basic/env-file.c`: `load_env_file → parse_env_file_internal → read_full_file`
(для257 :445/:452/:52), далее обычный VFS path open. Unit parser хранит пути,
а не cached file contents. Содержимое перечитывается при каждом `exec_spawn`,
в том числе отдельно для ExecCondition/ExecStartPre/ExecStart. При restart новый
main получает новый набор values. Пустой assignment EnvironmentFile= сбрасывает
ordered list; unit specifiers разрешаются parser `unit_path_printf` при загрузке.

### Ответы на обязательные вопросы

1. **Процесс:** PID1 system manager во всех пяти сборках. FIFO test удерживает
   reader до EOF, обнаруживает тот же inode в `/proc/1/fd`, затем передаёт только
   synthetic bytes. После этого actual child env/argv совпадают. FIFO — только
   диагностический барьер, production такой input должен отвергать.
2. **Namespace:** namespace/root manager при `exec_spawn`, до service mount setup.
   Поэтому bind, видимый только child/executor/private activator namespace, не
   решает задачу. Нынешнее требование activator=PID1 mount namespace сохраняется.
3. **Exec phases:** каждый condition/pre/main может получить другие bytes. IPC
   между этими процессами воспроизводит trusted → pre → main без задержек.
   Публиковать надо **до запроса restart**, держать через все команды до READY,
   а не начинать защиту после ExecStartPre.
4. **Кэш:** путь/порядок/optional state хранятся в loaded ExecContext; file values
   готовятся отдельно на каждый spawn. Next restart увидел later env в native test.
5. **Symlink:** разрешается при VFS open; native systemd follows symlink, в отличие
   от FIC openAbsolute O_NOFOLLOW. Это несовместимые допуски: поддержка systemd не
   основание разрешить symlink в первой FIC версии.
6. **Optional `-`:** loader пропускает safe_glob/load errors при ignore=true,
   не только ENOENT. Directory и dangling symlink дали отсутствие переменных
   без отказа старта; mandatory missing дал failure. Invalid variable diagnostics
   обрабатываются отдельно; `-` не обещает игнорировать любые произвольные warnings.
7. **Несколько files:** ordered list; glob matches обрабатываются в возвращённом
   sorted order; поздние assignments перекрывают ранние. Native tests проверяют
   literal order и `*.env` (one.env затем two.env). EnvironmentFile values
   перекрывают Environment=; итоговое UnsetEnvironment может их удалить — source
   semantics, отдельный native UnsetEnvironment test здесь не выполнялся.
8. **Paths:** абсолютные filename/wildcards; относительные пути отвергает parser,
   shell `~`/command substitution не выполняются. `%t` test разрешился в `/run`.
   Filename/glob closure и возможные новые matches требуют отдельного negative
   proof, не одного hash существующих matches. Первая FIC версия должна отказать
   glob; уже разрешённый literal specifier допускается только по pinned loaded path.
9. **daemon-reload:** может изменить loaded EnvironmentFiles между pre и main;
   native test показывает новый main env и различие **actual typed**
   `readLaunchContract(...)[launch.EnvironmentFiles]`. NeedDaemonReload=no не
   означает неизменность bytes или поколения контракта.
10. **После чтения:** pathname writer не меняет уже сформированный values vector,
    argv или environment другого процесса. Это подтверждено entry-barrier test.
    Ptracing/память PID1/executor/процесса, executable injection и arbitrary
    privileged interference за пределами данной гарантии. Одного byte pinning
    недостаточно, если меняются остальные launch sources; их уже pin текущий FIC.
11. **Когда можно cleanup:** manager больше не нуждается в файле после успешного
    его чтения для данного spawn. Но универсальный компонент не получает
    EnvironmentFile-read acknowledgement и служба ещё может читать config/сам
    envfile. Поэтому безопасный общий барьер остаётся подтверждённый новый READY
    с trusted service semantics и финальным proof; не «fork завершён» и не sleep.
12. **После READY:** fixture сохранила env и прочитанный digest после cleanup;
    последующий restart получил новые bytes. Если служба перечитывает файлы после
    READY, это вне однократного контракта; такую semantics нужно явно принять либо
    признать службу неподдерживаемой. ExecStartPost/restart-on-failure будущих
    экземпляров также нельзя автоматически включать в proof первоначального main.

## 4. Native PoC и доказательства A/B/C/D

[Набор и запуск](../tests/integration/verified_config_service/environment_file_research/README.md).
Fixture — отдельный notify/main unit `fic-env-research.service`, размещённый только
в `/run/systemd/system`, данные только `/run/fic-env-research`. Он получает
`FIC_ENV_WORD`, `FIC_ENV_CONFIG`, synthetic `SSHD_OPTS`; сообщает actual argv,
выбирает config, читает через FD, считает ContentDigest, сообщает mount ID/inode,
закрывает read FD и лишь по IPC-команде отправляет READY. Parent знает published
mount IDs и сравнивает **actual read FD**, а не поздний повторный open пути.

Использованы существующие MountSupport/hash/copy/observer, LaunchContract reader,
AtomicFileWriter и платформенный executable resolver. Не вызывается activate;
production validator не обходится новой разрешающей веткой. Snapshot publisher —
лабораторный механизм, не обещающий full activation status/recovery/lock/CAS loop.
Systemctl fixture setup использует ProcessExecutor без enrollment; production
VerifiedProcessExecutor остаётся обязательным на будущем этапе.

Матрица ниже — одинаковые 33 assertions/scenarios на каждой из пяти платформ,
а не результаты запуска штатного sshd.

| Проверка | Наблюдение / вывод |
|---|---|
| 1 actual reader | FIFO inode открыт у PID1; actual child получает заданное значение |
| 2 single env | environment, `${FIC_ENV_WORD}` argv, selected config SHA совпали |
| 3 multiple env | last file wins, argv соответствует effective value |
| 4 RO env+config, actual restart | новый InvocationID, config read FD имеет published mount ID; write env EROFS; cleanup после READY; running report стабилен |
| 5 original replaced после snapshot | AtomicFileWriter заменил inode; **production pre-bind identity gate обязан отказать**. Лабораторная публикация отдельно показала frozen original bytes, не успешную production activation |
| 6 rename during actual restart/pre | rename поверх file bind вернул EBUSY; новый main получил trusted value |
| 7 preopened original write FD | original bytes изменились за snapshot; main получил trusted copy; после cleanup чужая запись осталась, не «откатилась» |
| 8 mutate after manager read/before READY | после main-entry заменён envfile на foreign config path; main env/argv/config остались trusted |
| 9 mutate after READY/cleanup | текущий процесс неизменен; следующий actual restart получил later value |
| 10 optional absent | pre/main без переменной, запуск успешен |
| 11 optional appears between pre/main | pre без переменной, main получил appeared — отрицательный пример фиксации отсутствия только один раз |
| 12 optional appears before actual restart | absence check не защищает, новый процесс получил appeared |
| 13/14 optional/mandatory disappears before restart | optional стартует без переменной; mandatory restart fails |
| 15 protected parent absence | RO directory snapshot без entry блокирует create EROFS, main не получил переменную, после cleanup placeholder отсутствует |
| 16/17 empty optional/mandatory | оба дают пустой вклад в env и успешный start; mandatory empty отличается от missing failure |
| 18 optional directory | read error игнорируется; env пуст, start успешен |
| 19 optional dangling symlink | отсутствие target игнорируется |
| 20 optional mode000 | в root/CAP_DAC_OVERRIDE контейнере файл читается; это не доказательство идентичных прав для другого manager context |
| 21 empty ≠ absent filesystem | env одинаков, наличие regular object отличается и видно фазе pre; нет универсальной observational equivalence |
| 22 symlink | systemd прочёл target, FIC actual openAbsolute отказал |
| 23/24 synthetic SSHD_OPTS -f/-o | actual argv redirect выбрал foreign config; hash только good.conf недостаточен |
| 25 condition/pre/main | IPC меняет файл между фазами; каждый новый spawn перечитывает |
| 26 daemon-reload between phases | main получил новый input; typed launch list отличается |
| 27 startup exit | контролируемый exit23, failed state; READY не было |
| 28 READY deadline | fixture не отправила READY, настоящий systemd TimeoutStartSec сработал |
| 29 cleanup busy FD | ordinary umount дал EBUSY, cleanup=false, не Success; после закрытия FD retry успешен |
| 30 temporary foreign overmount/restore | main получил foreign env; до финального proof восстановлены исходный published mount ID/inode/SHA. Sticky MountObserver всё равно обнаружил event |
| 31/32 glob/specifier | sorted wildcard precedence и `%t` resolution подтверждены |
| 33 C control fixture | нет EnvironmentFile, fixed loaded Environment= формирует env/argv независимо от внешнего файла |

Барьерные гонки воспроизводятся не случайными sleep. Единственный bootstrap retry
runner — ожидание доступности systemd; timeout test использует реальный deadline.
Case30 имеет PASS как **успешно обнаруженный негативный сценарий**, не успешную
активацию чужой конфигурации. FIFO probe также намеренно неподдерживаемый в
production special file. Эти distinctions сохранены в названиях evidence cases.

### Четыре отдельных утверждения

Здесь буквы A–D обозначают proof claims, а не варианты архитектуры A/B/C.

| Claim | Что подтверждено | Что универсальный компонент не доказывает сам |
|---|---|---|
| A: manager получил правильные bytes | Source PID1 path open + защищённый неизменный RO object в его namespace за весь интервал; FIFO подтверждает reader; negative ABA показывает необходимость observer | Неизменность против arbitrary CAP_SYS_ADMIN, memory/ptrace и unobserved alternate namespace remount; pathname/hash endpoints сами по себе недостаточны |
| B: правильные env/argv | Реальные reports нового exec; source merge/serialization/substitution; pinned entire launch context обязателен | Желаемую policy семантику каждого значения; нельзя считать любые verified bytes безопасным `-f/-o`; UnsetEnvironment/другие inputs тоже влияют |
| C: main прочёл правильный config | Доверенная fixture читает FD, SHA и published mount ID совпали до READY | Произвольная служба может игнорировать config/READY semantics; полнота SSH closure — ответственность adapter, не generic activator |
| D: после READY можно снять защиту | Текущий fixture report не изменился после обычного cleanup, next restart видит новые bytes | Будущий reread, дочерние/ExecStartPost readers после READY, повторный auto restart, поздние admin действия не защищены |

Для **варианта A** claims A/B поддержаны при pinned inputs/namespace; C/D только
с trusted service/readiness и полной closure. Сам bind без списка/порядка/прочих
sources этих предпосылок не устанавливает.
Для **B** тот же механизм, дополненный явной проверкой этих предпосылок;
new production end-to-end proof пока отсутствует. Для **C** fixture подтверждает
loaded fixed env → B и trusted fixture C/D, а A про EnvironmentFile становится
неприменимым; это не доказывает owner-safe unit management или startup race proof.

## 5. Optional-absence — почему нужен отдельный дизайн

Existing file bind не может защищать отсутствующий inode/path: для target нужен
объект. Check absent → create before manager read — реальный воспроизведённый bypass.
Наблюдение mount namespace не замечает обычный create нового file; observer его
не заменяет. Проверять только до/после также допускает create/read/unlink ABA.

| Вариант | Оценка |
|---|---|
| Снимок всего родителя с отсутствующим entry | Native положительный proof отсутствия при RO directory; но `/etc/default` или `/etc/sysconfig` содержит чужие configs. Manifest, non-shared **его** parent (`/etc`), бюджет, symlink/ACL/labels, unrelated writers, package updates требуют отдельного широкого контракта |
| Запрет появления объекта через pathname checks | Не является атомарным запретом; без VFS protection отвергнуть |
| Защищённый empty replacement | Для env contribution данного parser часто равен absent, но файловая наблюдаемость/mandatory failures/errors отличаются; bind на отсутствующий target всё равно требует parent overlay/placeholder. Не создавать persistent placeholder; универсальная подмена не принимается |
| Refuse optional-absence | Рекомендовано для первой версии: fail-closed до mount, отсутствие не превращается в ownership или config mutation |
| Managed launch без envfile | C исключает отсутствие из read contract, но требует заранее явно управляемого launch model и unit ownership |

Права/ошибки: mandatory missing не равен empty; optional directory errors подавляются,
root mode000 в данном privilege context не равен «unreadable»; regular empty может
иметь другую metadata и быть видимым shell/pre command. `-` подавляет loader errors
без собственного failure-log в exec_spawn, но invalid env assignment logging отдельное.
Это source+native findings, не утверждение об одинаковых journal messages для всех
возможных filesystem errors. Нативный mandatory unreadable под непривилегированным
manager, ACL/SELinux и error-log exhaustiveness здесь `NOT_TESTED`.

## 6. Сравнение архитектурных вариантов

| Критерий | A: дополнительный file bind | B: launch-input contract + A | C: managed launch |
|---|---|---|---|
| Stock units | Сохраняет | Сохраняет | Нужен заранее согласованный unit/drop-in/launcher contract |
| Existing optional | Работает, если присутствует и protected | Явное present-only правило | Можно убрать file dependency |
| Optional absent | Сам не защищает | Fail-closed v1; directory absence отдельный будущий scope | Возможен fixed environment без file, semantics надо согласовать |
| TOCTOU | Защищает bytes внутри RO window, не доказывает input closure | Закрепляет список/порядок/optional flags/покрытие; те же accepted mount/contract residuals | Переносит proof на loaded env/argv и unit provenance; source/manager ABA остаётся |
| Сложность | Механизм уже есть, но неполный acceptance | Средняя: validation/orchestration/tests, без второго publisher | Высокая: ownership, packaging, admin conflicts, lifecycle |
| FIC changes | Добавить file target недостаточно: validator всё ещё отказал бы | Узкий внутренний classifier и proof coverage; public API можно сохранить | Новый отдельный owner запуска, не side effect activate |
| Packaging | Parent boundaries для envfile paths | То же; `/etc/default`, ALT `/etc/sysconfig` не забыть | Управляемые units/drop-ins и package upgrade protocol |
| Ownership/rollback | Только временная публикация, persistent owner прежний | То же, fail-closed при несовпадении/partial cleanup | Новое явно учтённое владение unit, CAS/release/rollback отдельно |
| Debian/Ubuntu | Source mechanism пригоден | Предпочтительно для существующих literal files | Возможен, но меняет admin contract; Ubuntu sockets отдельно |
| ALT | Envfile mechanism пригоден | То же | Сам не даёт notify в штатной binary; readiness отдельно |
| Ограничения | Без B не знает, что все inputs покрыты | Нет v1 absent/glob/symlink; common namespace/private parents | Нельзя временно подменять штатный запуск молча; transient unit меняет identity |

C может сохранить имя штатной службы при **заранее** установленном managed drop-in:
сбросить EnvironmentFile, задать фиксированные Environment/ExecStart. Но установка/
изменение такого контракта требует explicit daemon-reload, version/ownership,
разрешения конфликтов с administrator overrides и distro updates. В текущей
fixture проверен только static environment control case. Production unit manager
не реализован и не предлагается частью activate. Runtime D-Bus property setters
тоже меняют launch model/загруженный state и нередко создают runtime settings;
это не безвредная передача «ещё одного argv». Transient service получает другое
имя/cgroup/lifecycle, что не сохраняет stock service identity автоматически.

## 7. Границы безопасности и ответственность FIC

Текущая архитектура остаётся:

* policies задают desired values; transaction backend пишет persistent config;
* activator проверяет однократный запуск, не записывает и не «откатывает» envfile;
* ownership/journal/recovery persistent файлов остаются у прежних backend;
* чужая запись в скрытый original не должна теряться после cleanup;
* unit changes не являются скрытым side effect SSH apply;
* saved/applied/cleanup различаются, partial failure не превращается в Success.

Исследованы существующие `SshRuntime` reload semantics, `SshInputAuthority`,
`SshConfigAudit`, profiles, `AtomicFileWriter`, `ContentDigest`,
`VerifiedProcessExecutor`: **ничего не переписано**. Новому snapshot engine нет
оснований. AtomicFileWriter same-filesystem sibling rename вне active file bind
сохраняется; rename поверх mounted target во время окна EBUSY — ожидаемо, поэтому
FIC writers должны сериализоваться existing locking. Чужой writer в оригинал
не становится владельцем snapshot, а activator не становится rollback owner.

Mount proof не абсолютен. Case30 показывает реальную недостаточность endpoint
SHA **и** endpoint ID без sticky observer. В текущем same namespace observer
обнаруживает temporary foreign overmount даже после восстановления. Существующие
blind spots (например, некоторые remount через другой namespace), последовательные
contract checks/restart, check/attach и identity-check/umount race не устранены
PoC. Нет основания обещать защиту от произвольного CAP_SYS_ADMIN или тайного
memory modification. Если будущие требования расширятся до такой модели,
варианты A/B без новых механизмов нельзя объявлять достаточными.

Private boundaries остаются deployment prerequisite: `/etc/ssh`/`/etc/openssh`
недостаточно для envfile в `/etc/default`/`/etc/sysconfig`; их publication parents
и runtime workspace тоже должны быть безопасны. Whole-directory absence target
требует boundary на **его родителе**, а не mount на самой directory-цели.
Нельзя создавать permanent boundaries автоматически или менять global propagation.
В этом PoC `/run` уже private; ordinary shared-root host deployment не испытывался.

## 8. Конкретное ТЗ следующего production этапа

Scope: standalone activator + его tests/docs; **без подключения к SSH/policies**.

1. Сохранить `ActivationRequest` и `ActivationResult` v1. Существующие `paths`
   могут содержать expected-SHA envfile files наряду с service config. Не вводить
   публичные ControlledLaunchInputs, пока нет реального неподдерживаемого use case.
2. Внутренний classifier из **typed loaded** `EnvironmentFiles a(sb)` сохраняет
   order/дубликаты/optional flags; для каждого элемента требует absolute normalized
   literal regular existing input, matched request file target с reference SHA.
   Непокрытый/absent/symlink/glob input — UnsupportedConfiguration до первого mount.
   Дубликаты пути не удалять из semantic list; target хранится один, порядок остаётся.
   Поддержку envfile внутри directory target лучше оставить отдельным явно
   протестированным расширением; v1 exact file target проще проверить.
3. Узко заменить существующий blanket EnvironmentFiles rejection этим classifier;
   все прочие credentials/triggers/sandbox/identity/namespace/trust gates сохранить.
   Не выдавать permissive validator до подтверждения complete target coverage.
4. До restart опубликовать все verified config **и** launch file targets существующим
   механизмом. Сохранить оригинальные identity/CAS checks, aggregate byte budget,
   exact tree checks, non-shared parents/workspace, sticky observer и final RO proof.
5. Закреплять EnvironmentFiles contract и unit/manager environment/provenance
   перед запросом, после запроса, при readiness и final proof как сейчас.
   Loaded change → InterferenceDetected, не автоматически reload/retry/fallback.
6. READY относится к новому InvocationID/MainPID, с trusted service semantics.
   Unmount только после полного proof; failure/timeout тоже выполняет owner-safe
   cleanup. Cleanup error никогда не Success, primaryStatus сохраняется.
7. Не парсить envfile новым упрощённым «shell parser» внутри generic activator:
   systemd отвечает за interpretation verified bytes; требование допустимого
   effective argv/`-f`/`-o`/Include принадлежит будущему SSH adapter. Его reference
   не генерировать из произвольных observed bytes.
8. Не добавлять migration, placeholder, unit/drop-in management, fallback
   reload/start, optional-absence support или новые policy dependencies.
9. Docs явно разделяют утверждения A/B/C/D, present-only scope и accepted residuals.
   Отдельно проверить exact source protocol при поддержке новых systemd versions.

Ожидаемый объём: локальные изменения LaunchContract validation и activator
preflight/orchestration + отдельные regression cases в существующем native gate;
возможно маленький внутренний helper, если этого требует разделение проверки.
Не требуется переписывать tmpfs, public API, Systemd restart protocol, policy
transaction/ownership/rollback/MutationJournal или packaging units. Deployment
parent-boundary preparation — отдельное ТЗ. Ubuntu socket activation и ALT
Type=simple также остаются независимыми блокерами, не исправляются envfile support.

### Native regression acceptance будущей реализации

* Пять distro userspaces, exact systemd sources, затем полноценная shared-root VM
  с подготовленными boundaries; common WSL kernel не заменяет real kernel matrix.
* Сам **production activate**, существующий running fixture и настоящий restart:
  actual env/argv/config FD SHA/mount ID, новый InvocationID, READY, cleanup.
* По каждому existing envfile literal order/duplicate/optional-present и отрицательные
  absent/glob/symlink/uncovered/metadata/ACL/label/nested mount/parent propagation.
* Изменение списка/optional flag/order, Manager.Environment/UnsetEnvironment/unit
  argv/fragment/drop-ins; daemon-reload в разных phases; envfile content change
  без daemon-reload. Сохранить original identity rejection before bind.
* Same namespace overmount ABA обязан завершиться InterferenceDetected; повторить
  ранее известные alternate-namespace negatives/limitations без ложного Success.
* Original rename/preopened FD, protected write EROFS, partial publication,
  READY timeout/start failure, cleanup EBUSY/foreign replacement, no residual adoption.
* Immutable env/argv после manager read, config read до READY; future reread/restart
  явно вне результата. Не объявлять тест fixture proof для неизвестного SSH binary.
* Не меняются старые reject cases, trust enrollment, persistent state или
  saved/applied semantics; full build/CTest после реального production изменения.

## 9. Выполненная validation / что не проверено

Выполнены configure/build `environment_file_research` и runner во всех пяти
контейнерах; 33 PASS/0 FAIL каждый. Bash syntax, evidence case-set consistency,
source metadata SHA256, scope review и git diff --check. Единственный итоговый
research commit, no push. Исследовательская suite автономна; existing CI targets
не изменены, старые production regressions не удалены/ослаблены.

Не выполнялись: production activate, штатный SSH restart/изменение config/units,
policy apply/rollback, CommandHashStore enrollment, real host mounts, global
propagation changes, persistent mounts, LSM/eBPF/auditd. Специальные fixture units
и daemon-reload допустимы **только внутри disposable контейнеров**, удаляемых
runner trap. Full project build/CTest не запускались: production untouched;
будущий production этап обязан выполнить соответствующие gates.

NOT_TESTED: real VM/physical distro kernels, reboot/package upgrades,
enforcing SELinux/ACL support, root/user manager alternatives, strict protection
against privileged memory/namespace attacks, full crash-consistent recovery,
actual SSH -f/-o parser/runtime (здесь synthetic fixture), Ubuntu socket coordinator,
ALT notify implementation, универсальный management/rollback варианта C и
production optional-absence directory lifecycle.
