# Проверяемые примитивы M1

Эти компоненты — основание package coordinator. Пока coordinator, startup fence
gate и recovery не подключены, они **не обеспечивают безопасность действующего
package lifecycle FIC**. Пакетная архитектура описана в
[maintenance-runtime-package-design.md](maintenance-runtime-package-design.md),
retry contract — в [maintenance-finalizer-retry-lifecycle.md](maintenance-finalizer-retry-lifecycle.md).

## Admission и package database

`DaemonInstanceLock` выдаёт authority только приобрёвшему его процессу, а не
fork-потомку. `PackageLifecycleStore` хранит типизированные фазы и durable retry
admission под этим guard. Это storage API: переход в `Installed` или
`RemovedTombstone` сам по себе не является domain proof. Его обязан проверять
закрытый coordinator.

`PackageManagerTransactionLock` удерживает реальные POSIX write locks:

* DEB: `/var/lib/dpkg/lock-frontend`, затем `/var/lib/dpkg/lock`;
* ALT: `/var/lib/rpm/.rpm.lock`.

Файлы должны уже существовать: regular, root:root, single-link, без group/other
write. Компонент не создаёт, не обнуляет и не удаляет lockfiles. Проверяет identity
после получения всех locks и перед окончательным proof. Busy — временный отказ;
невозможность доказать lock identity не разрешает finalization. Нельзя повторно
открывать/закрывать эти inode в том же процессе: POSIX lock снимается при закрытии
любого descriptor этого inode. Поэтому есть также process-local exclusion.
Read-only `dpkg-query`/`rpm -q` в дочернем процессе совместимы с удержанием locks.

## Persistent masks

`PackageWriterUnits.h` содержит единый закрытый список пяти units: daemon,
device daemon, notify dispatcher и оба device collector/reconciliation oneshot.
`PackageUnitMasks` сначала сохраняет immutable ledger и уникальный пустой artifact
в root-private operation directory. Только затем публикует exclusive symlinks
в `/etc/systemd/system`. Существующие `/dev/null` и empty-file masks сохраняются
по identity. Custom overrides не заменяются. Неизвестная/повреждённая provenance
означает отказ, а не разрешение на удаление mask.

Publication/restore идемпотентны после частичного выполнения. Restore удаляет
только собственные mask links; чужая подмена остаётся нетронутой. Артефакты и
ledger не удаляются. Crash до завершения ledger может оставить приватный orphan:
это не даёт права присвоить его при recovery. Остаточная гонка между условной
проверкой link и unlink против независимого privileged writer остаётся; FIC-lock
сериализует только cooperative FIC writers.

## Остановка и quiescence

Работающий cooperative daemon сам удерживает `daemon.lock`. Поэтому допустим
только фиксированный stop request перед admission, без открытия journal и без
release/fence/resource writes. После stop нужно получить admission, опубликовать
и доказать persistent masks и заново проверить всех writers. Свободный lock не
заменяет проверку legacy processes.

`PackageWritersQuiescence` требует root, systemd PID1, общий mount/cgroup namespace
с manager и genuine cgroup v2. Неизвестное окружение отвергается. Выполняются:

1. Успешный `systemctl show`, точные unit identity и terminal state, нулевые
   MainPID/ControlPID, отсутствие Job. Один `is-active` не используется.
2. Проверка `cgroup.events populated=0` всех найденных FIC unit cgroups, включая
   descendants. Это ловит оставшийся child при `KillMode=process`.
3. Census genuine `/proc` в том же PID namespace: root/capable processes,
   kernel executable identity, starttime и повторная проверка executable.
   Известные имена writers и byte-identical переименованные legacy images
   отвергаются; inventory никого не завершает.

Legacy images нужно захватить до unpack и сохранить в lifecycle provenance.
Сам census не запрещает будущий ручной запуск старой копии: административный
запрет независимых legacy launches остаётся deployment prerequisite. Zombie
leader не доказывает отсутствие live worker threads: при недоступном `exe`
проверяется весь task group.

Стоимость ограничена: systemctl ≤5 s/64 KiB на вызов в пределах общего deadline;
cgroup inventory ≤4096 каталогов/262144 entries/depth64; process inventory
≤4096 processes/tasks, 16 MiB metadata, 256 MiB fingerprints, 64 MiB/image,
≤8 legacy images. Превышение — отказ без release, не усечение proof.

## Validation boundary

Root/unit tests проверяют реальный flock/fcntl, CAS/durability, fork authority,
SIGKILL на durable фазах, mask ownership и настоящий procfs. Native component
probes в `tests/integration/maintenance-lifecycle/` используют disposable systemd
containers пяти дистрибутивов и только dummy units. Они проверяют masks,
quiescence, surviving child, command timeout и manual-copy refusal. Перезапуск
PID1 контейнера не является kernel reboot/power-loss proof. Успешные component
tests не заменяют actual FIC install/upgrade/erase/finalizer/recovery gates.
