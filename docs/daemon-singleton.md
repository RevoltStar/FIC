# Ранний daemon singleton и границы standalone-команд

## M1-A: read-only pre-stop preflight

Четыре `*-prerm-prepare preflight` открывают отдельный journal через
`validatePersistentStateReadOnly()`. Они не используют operational singleton,
не bootstrap/recover/migrate journal/witness. Virgin/corrupt provenance даёт
fail-closed отказ без изменения persistent state. Release по-прежнему открывает
fresh operational journal; preflight не является разрешением на stale release.

Native regression запускает настоящие четыре CLI routes на virgin/corrupt state,
сравнивает persistent snapshots и требует отказа. Baseline RED: DM preflight
создавал provenance до отказа backend. GREEN: все четыре route read-only.
Это исправление не закрывает package-wide gap или legacy writer fencing.
Дальнейший M1 admission/recovery рассматривается отдельно.

## Контракт daemon mode

Один daemon process FIC удерживает `/run/fic/daemon.lock` (точнее,
`FicRuntimePaths::get().runtimeDir / "daemon.lock"`) от начала startup до выхода.
Lock не зависит от `--socket`, готовности IPC или состояния journal. У второго
экземпляра занятый или недоверенный lock означает немедленный отказ до config
validation, startup failure containment, incident reconciliation, MutationJournal,
registry/apply и создания socket. Он не должен даже блокировать SSH при отказе startup.
До lock выполняются только чтение аргументов/профиля/host compatibility и memory-only
инициализация runtime paths. Создание инфраструктуры самого lock — единственная
разрешённая запись для его приобретения.

`DaemonInstanceLock` — noncopyable RAII object в области `main`, не временный объект
внутри ветки startup. Проверяется абсолютный нормализованный путь без `..`;
каждый каталог открывается относительно pinned descriptor с `O_NOFOLLOW`, должен
принадлежать root и не разрешать group/other write. Создаётся только отсутствующий
последний runtime-каталог (0755 до umask); недоверенные каталоги не исправляются.
Lockfile открывается без truncate, с `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, должен быть
regular, root-owned, mode 0600, single-link. После неблокирующего
`flock(LOCK_EX|LOCK_NB)` повторно проверяется named/pinned inode identity и metadata.
Ошибка/занятость не разрешает fallback на socket или PID из файла.

Descriptor удерживается всю жизнь daemon и закрывается RAII/ядром при exit/crash.
File не удаляется, PID не используется как authority; после crash новый процесс
приобретает тот же inode. Destructor использует close, не явный LOCK_UN: закрытие
унаследованной копии FD после fork не снимает lock у родителя; exec закрывает FD
благодаря CLOEXEC. Долгоживущий fork без exec может продлить lifetime lock до закрытия
последней inherited копии; это безопасный отказ в доступности, не разрешение второго
writer. Текущий daemon не вводит такого background fork этим изменением.

Гарантия относится к daemon instances с общей production runtime directory и общим
filesystem namespace. Root, меняющий/удаляющий сам lockfile, каталоги или mount
namespace, находится вне этой модели. Не обещается глобальная межпроцессная
атомарность journal/CAS или сериализация всех executable components FIC.

Read-only flags, `--maintenance` и trust-sync не захватывают daemon singleton;
их маршруты/packaging lifecycle в этом коммите не изменены. CLI/GUI используют IPC,
а не становятся независимыми policy writers. SSH Stage 3A пока не реализован:
общий process-local SSH mutex и Prepared gate остаются следующим отдельным этапом.

## Read-only аудит standalone entrypoints

Ниже — исходный аудит `90f8207`, сохранённый как обоснование M1. Текущие
исправления M1-A/B и оставшиеся ограничения описаны в
[maintenance-admission.md](maintenance-admission.md): preflight уже read-only,
а перечисленные exclusive standalone writers получают daemon.lock. Это ещё не
package-wide coordination; legacy/manual writers и package scripts остаются
отдельной незавершённой частью. Таблица ниже не является текущим перечнем гарантий.

Это аудит исходников, не доказательство native package lifecycle. Обозначения:
**RO** — чтение managed state; **RS** — существующая resource serialization;
**STOP** — mutation, безопасный контракт которой требует остановленного daemon.
RS не означает сериализацию всего shared MutationJournal. Lock/log infrastructure
может иметь side effects даже у observation-команды; такие случаи указаны отдельно.

| Команда / действие | Класс | Фактическая защита и ограничение |
|---|---|---|
| `--version`, `--build-info`, `--trust-list-platform-paths` | RO | Выход до singleton и runtime initialization |
| `--trust-sync-platform`, `--trust-sync-platform-affected` | RS | `PackageTrustSync` → `CommandHashStore::updateHashes`: existing ExclusivePidLock на commandhash.txt.lock, reload/edit/atomic save под lock. Не пишет MutationJournal. Package ownership verification вне hash-store lock не превращается в global package transaction |
| `--maintenance check-config` | RO | `ConfigSchemaManager::verifyConfigs`, без ensure/migration |
| `--maintenance wait-daemon` | RO | IPC status client; не standalone writer |
| `incident-pam-verify`, `incident-pam-prove-detached` | RO | Проверка account topology; не attach/detach |
| `incident-pam-alt status` | RO | Trusted snapshot/inspect account file |
| `incident-pam-alt attach/detach` | STOP | Snapshot/CAS и compensation, но нет общего lock с live PAM/incident writers; CAS не заменяет whole-operation serialization |
| `incident-init` | STOP | Exclusive-create authoritative incident state + durability; существующее состояние не перезаписывается. Нет daemon lifetime interlock; bootstrap требует lifecycle coordination |
| `ensure-config`, `ensure-config-first-install` | STOP | Config bootstrap/schema handling; нет общей блокировки с daemon configuration mutation |
| `bootstrap-pam-password-slots` | STOP | Создание отсутствующих canonical-neutral slots; existence exclusivity не сериализует весь PAM lifecycle |
| `validate-pam-slots-before-attach` | RO | Attachment inspection с journal provenance; reader не запрашивает operational journal bootstrap |
| `dm-prerm-prepare preflight` | STOP (*) | Backend preview под existing DM resource lock, но entrypoint сначала вызывает operational `tryGet()` journal |
| `dm-prerm-prepare release` | STOP | DM resource lock есть; scope invalidation/shared journal не защищены daemon singleton между процессами |
| `desktop-prerm-prepare preflight` | STOP (*) | DE preview; сначала operational journal access; не гарантирован строго RO entrypoint |
| `desktop-prerm-prepare release` | STOP | GNOME/FLY используют desktop-config.lock; общий journal и lifecycle целиком не межпроцессно защищены |
| `pam-provider-prerm-prepare preflight` | STOP (*) | Сам backend preflight RO и не берёт mutation lock; entrypoint сначала operational journal access |
| `pam-provider-prerm-prepare release` | STOP | Shared pam-provider-managed.lock с provider apply/rollback, но journal загружен до него и shared между backend |
| `pam-password-prerm-prepare preflight` | STOP (*) | Сам package preflight RO; entrypoint operational journal access |
| `pam-password-prerm-prepare release` | STOP | Package-release lock + внутренние проверки; код прямо требует stopped daemon; это не общий journal interlock |
| `pam-alt-faillock status` | RS (observation) | Existing topology ExclusivePidLock; managed state читается, lock/debug infrastructure может писаться |
| `pam-alt-faillock enable/disable` | RS | Shared topology lock с соответствующим backend; нет записи MutationJournal из manager; не гарантия сериализации joint PAM lifecycle |
| `pam-alt-pwhistory status` | RS (observation) | Topology lock + transaction file lock при enabled history; lock/debug infrastructure имеет side effects |
| `pam-alt-pwhistory prepare/enable/disable` | RS | Topology lock; storage/history дополнительно transaction file locking. Это resource-specific защита, не daemon-wide/journal protection |
| Неизвестные maintenance command/action | RO (отказ) | Не становятся daemon mode и не получают новый fallback |

(*) **Подтверждённый дефект границы RO:** `main.cpp` вызывает
`DaemonMutationJournal::tryGet()` перед preflight. Это operational API с
`initializeOrLoad()`: на virgin journal/witness оно может создавать persistent
provenance. Следовательно строго RO backend не делает весь standalone entrypoint
строго RO. Штатные prerm вызывают эти preflight до stop. На здоровом существующем
journal это не доказательство постоянной записи при каждом вызове, но общий
read-only контракт нарушен наличием write-capable initialization route.

## Аудит package scripts и подтверждённые дефекты

Исследованы `packaging/deb/build-fic-debian12-deb.sh`,
`packaging/rpm/build-fic-alt-p11-rpm.sh` и RPM trust-sync filetrigger. Изменений в них нет.

* Debian preinst/postinst останавливают известные systemd units перед config/PAM
  maintenance; postinst затем делает bootstrap/проверки/trust-sync и запускает units.
  Triggered trust-sync вызывается отдельно, без stop, и имеет hash-store resource lock.
* Debian remove/prerm: DM/DE/provider preflight до stop; затем disable --now,
  bounded ожидание и проверка `is-active`, затем DM/DE/provider/password release
  до detach hooks. Ошибки stop первоначально подавляются, финальная проверка active
  присутствует. При отсутствии systemctl эта ветка пропускается. `is-active` nonzero
  также не доказывает успешный запрос менеджеру или отсутствие terminating/manual
  process: полного подтверждения остановки **всех** writers нет.
* RPM pre/pre-upgrade/postinst останавливают active известные units до maintenance
  и проверяют exit code stop. Это не обнаруживает независимо запущенный daemon.
* **Подтверждённый дефект RPM erase:** `system_integration_symlink_preun_script`
  выполняет `disable --now ... || true`, не проверяет stopped state и затем безусловно
  запускает post-stop hook с DM/DE/provider release и incident detach. При stop failure
  либо отсутствии systemctl release всё равно достижим. Комментарий «все writers
  остановлены» сильнее реальной shell-проверки.
* **Подтверждённый межпроцессный пробел standalone release:** root может запустить
  любой `*-prerm-prepare release` при работающем daemon; entrypoint не проверяет
  его остановку и не берёт singleton. Resource locks некоторых backend не защищают
  всю загрузку/finalization общего journal от другого backend/другого процесса.
  Поэтому реально существует write-capable route к тем же ресурсам/MutationJournal
  параллельно daemon без достаточной общей serialization. Это вывод по call graph,
  а не воспроизведение потери journal на живой системе. CAS/durability checks не
  следует называть гарантией whole-operation exclusion.
* ALT incident attach/detach и config bootstrap доступны вручную без stopped-daemon
  admission. Их package placement не является проверкой внутри binary.
* Новый singleton не приобретён maintenance-командами по явно согласованной границе.
  Имеющиеся resource locks (включая legacy ExclusivePidLock) не hardened этим коммитом;
  hash-store serialization не означает безопасную конкуренцию произвольных maintenance.

### Обязательные следующие задачи

1. Согласовать отдельный maintenance/package admission protocol со stopped-daemon
   proof и защитой shared journal на всю операцию, включая его initial load.
2. Сделать preflight entrypoints действительно read-only: отделить inspection от
   operational journal initialization/recovery. Не добавлять обход provenance.
3. Исправить RPM post-stop release admission и усилить Debian proof для ошибок
   manager/stop, terminating states, отсутствия manager и manual daemon writers.
4. Согласовать координацию config bootstrap/ALT incident topology с daemon; отдельно
   проверить scope достаточности существующих resource locks, без обещания global safety.
5. Только затем расширять cross-process claims; отдельно вернуться к SSH Stage 3A
   с общим process-local mutex и service-wide Prepared admission.

## Проверки singleton

`daemon_instance_lock_tests` использует root-owned уникальные fixtures в `/run`,
реальные процессы и pipes как barriers: нормальный release/restart, занятый lock,
одновременный старт двух процессов, SIGKILL/restart, исключение, чужой owner/mode,
symlink/parent symlink, hardlink, FIFO/directory. Никаких sleep; watchdog 25s/CTest 30s.
Без root root-specific cases дают явный SKIP, не ложный PASS.

`daemon_singleton_startup_static_checks` закрепляет границу в production main.
`daemon_singleton_startup_native` — opt-in только в disposable root container
(`FIC_DAEMON_SINGLETON_NATIVE=1`): настоящий fic с занятым guard отказывает с default
и custom socket. Проверяются security-file snapshots, сохранение read-only flags и
maintenance check-config, crash holder и повторное получение lock. Никакого
успешного real policy apply/reload на хосте разработчика.

Validation этого коммита: Debian12 full configure/build и полный CTest с native
opt-in — 191 PASS/0 FAIL/1 ожидаемый generic native SKIP (192 total), 170.99s;
все три новые проверки PASS. Лог `/tmp/fic-singleton-full-debian12.log`.
Дополнительно Debian13: native C++17 `-Wall -Wextra -Werror` build и process suite
PASS (`/tmp/fic-singleton-debian13.log`). `git diff --check` PASS.
Не выполнялись real package erase/upgrade, успешный startup/apply live daemon,
SSH/PAM native activation или проверки других kernels. Maintenance findings
выше подтверждены исходниками, не экспериментом с потерей данных на живой машине.
