# Ранний daemon singleton и границы standalone-команд

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

CLI/GUI используют IPC и не становятся независимыми policy writers.
Текущий перечень standalone routes, admission и resource barriers описан в
[maintenance-admission.md](maintenance-admission.md), package lifecycle — в
[package-lifecycle.md](package-lifecycle.md). Старые offline `*-prerm-prepare`
entrypoints удалены. Не трактовать singleton как защиту от произвольного старого
или изменённого privileged executable, который не соблюдает admission protocol.
