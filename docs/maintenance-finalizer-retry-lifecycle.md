# M1: retry/recovery deferred finalizer

## Статус и граница

Целевая архитектура: закрытый C++ oneshot + асинхронные package hooks +
`systemd.path` + boot rescan + повторяемый timer. Постоянного watcher нет.
Этот контракт заменяет конечный общий бюджет попыток из первоначального исследования.
Реализация production package-session/finalizer ещё не завершена. Native fixtures
проверяют transport и модель повторов, **не безопасность реального FIC finalizer**.

## Состояния и результаты

Durable lifecycle fence и retry metadata — разные вещи. Cooldown, событие или
успешный запуск oneshot никогда не разрешают daemon startup.

| Состояние | Условие | Следующее действие |
|---|---|---|
| InstalledButFenced / Waiting | Package transaction занята, lock недоступен, half-configured, недоступен источник proof, timeout/I/O failure | Сохранить fence; повторять автоматически без общего лимита числа попыток |
| Blocked | Доказанная структурная ошибка: corrupt/unknown fence или journal, invalid provenance, противоречивый окончательный manifest, неоднозначные версии после quiescence | Сохранить fence и диагностику; не повторять дорогие proofs/мутации автоматически |
| ReadyToProve | Writers остановлены/fenced, package manager quiescent, установлен ожидаемый согласованный набор пакетов | Под daemon.lock выполнить ВСЕ свежие proofs; это ещё не разрешение startup |
| Completed | Journal/PAM/incident/manifest proofs успешны, нет незавершённых критических операций | Durable completion → unlock → штатный daemon start |
| RemovedTombstone | Release доказан; отсутствие пакета не является разрешением startup | Tombstone сохраняется вне package-owned paths; install/recovery только закрытым flow |

Waiting — результат попытки, а не permission на recovery write. Ошибка чтения не
становится доказательством повреждения. Несовпадение версии при занятой transaction
не считается постоянной ошибкой. Half-configured после failed postinst продолжает
ожидать исправления через package manager; timer не запускает configure/repair сам.
Неизвестный результат никогда не трактуется как SUCCESS. Если его нельзя доказанно
классифицировать, fence сохраняется и публикуется явная диагностика.

Blocked не переходит в Completed от изменения package DB, нового события или reboot.
Повторное дорогое восстановление допускает только закрытый install/reinstall/
abort-recovery flow с новой generation, под тем же daemon.lock, после проверки
исходного состояния и всех необходимых proofs. Никаких force/unblock-флагов,
автоматического adoption ownership или перезаписи повреждённого provenance.
При нечитаемом fence нельзя доверять и содержащимся в нём retry metadata.

## Quiescence во время финальных proofs

Разовая проверка «package lock свободен» недостаточна: сразу после неё может начаться
новая transaction. Finalizer должен неблокирующе приобрести настоящие, descriptor-
и identity-проверенные package-manager transaction locks и удерживать их до durable
completion, совместно с daemon.lock. Если приобрести весь набор нельзя — освободить
полученное и вернуть Waiting. Никакого ожидания package manager под daemon.lock.
Набор/тип locks и возможность read-only queries при их удержании требуют native
проверки отдельно на DEB и ALT RPM. Исследовательский FREE/HELD probe это не доказывает.
Любая ошибка acquisition/query сохраняет fence. Package-session, вызываемая самим
package manager, не снимает fence и не пытается захватить locks родительской transaction.

## Частота, стоимость и crash

Production defaults для реализации: минимальный интервал дорогих попыток **60 s**,
общий deadline одной попытки **30 s**, отдельного внешнего proof command **5 s**,
совокупный захваченный output не более **1 MiB**. Это выбранные ограничения нового
компонента, не заявление о текущих defaults ProcessExecutor. Deadline включает
суммарное время команд; 5 s не умножается бесконтрольно на число команд. Нет
ожидания package transaction под daemon.lock. Захват lock неблокирующий.
Файловые read limits также обязательны; потенциально неограниченный manifest/proc
scan должен завершиться отказом при исчерпании budget. Изменение этих defaults
требует актуализации contract tests.

* До дорогих proofs записывается durable admission: operation/generation, boot ID,
  CLOCK_BOOTTIME timestamp. Один daemon.lock сериализует решение и запись.
* На той же boot cooldown нельзя сбросить перезапуском helper, hooks, path events,
  manager reexec или wall-clock adjustment. Crash после admission расходует текущий
  интервал, но **не лишает operation последующих попыток**.
* Новая boot допускает одну initial попытку после проверки текущего fence. Неверный
  timestamp/format в текущей boot — отказ, не разрешение обхода cooldown.
* Cooldown/Blocked/Completed обработка дешевая: trusted bounded read + диагностика;
  без journal initialization, resource writes и полного manifest/process scan.
* Нет счетчика, после которого временное ожидание становится DeliveryExhausted.
  Для временной недоступности deadline относится к попытке, не ко всей operation.
* Повторяющийся timeout/crash не разрешает снять fence; timeout сам по себе не
  доказывает структурную порчу. Диагностика хранит причину/счётчик без log storm.
* systemd TimeoutStartSec — внешний предел зависшей попытки, дополняющий внутренние
  deadlines. Обычный SIGKILL не доказывает завершения D-state kernel I/O: при таком
  отказе liveness не обещается; fence продолжает защищать startup.

Это ограничение частоты **дорогих попыток**, не защита от privileged caller,
который бесконечно вызывает helper/systemctl. Hook/path noise не должен создавать
дорогую работу или продлевать cooldown записью на каждый отклонённый сигнал.

## Доставка

Timer всегда устанавливается и включается вместе с finalizer. `OnBootSec=60s` +
`OnUnitInactiveSec=60s`, `AccuracySec=1s`, закрытая фиксированная service. Повтор
отсчитывается после завершения service (включая failure), а не от времени начала.
Boot rescan независим от `.path`; для позднего enable уже истёкший OnBootSec даёт
initial attempt. Монотонный timer не полагается на `Persistent=` calendar semantics.

Обычные Waiting/Blocked завершают service штатно, но с отдельным диагностическим
результатом; transport exit 0 не означает lifecycle SUCCESS. Для crash не нужен
неограниченный `Restart=` loop: timer продолжает recovery. Service start limiter
не должен навсегда выключать timer-попытки; в проверенной модели
`StartLimitIntervalSec=0`, rate/cost gate расположен внутри helper. Path trigger
limiter может отключить шумную `.path`, но timer от неё не зависит.

Hooks только асинхронно запрашивают фиксированную unit. Нельзя ожидать родительский
apt/rpm из hook. Ни hook, ни event не доказывают quiescence. Timer включается до
выхода postinst; failure этого шага — явная ошибка установки с сохранённым fence.
После package manager return может наблюдаться InstalledButFenced до свежих proofs.

Lost/coalesced event во время oneshot, atomic replacement, watch loss и пропущенный
hook не исчерпывают доставку: timer всё равно снова запросит service. Crash/reboot
требует boot-enabled timer, manager reexec сохраняет timer; отсутствующий/сломанный
helper оставляет unit failed и fence. Package verification должна обнаруживать
сломанные delivery artifacts. Чисто событийная доставка больше не предполагается.

**Liveness:** при установленном исправном helper/timer, работоспособном systemd/FS,
fair scheduling и eventual доступности всех proofs после конечной transaction
новая попытка произойдёт без нового внешнего события, независимо от её длительности.
При устойчивом Waiting и дешёвом отказе обычная задержка — один timer interval с
AccuracySec; это не realtime SLA. Infinite crashes, administrative masks, потеря
бинарника/FS, неустранимые structural errors исключены из liveness, но не разрешают
снять fence. Общее число попыток не ограничено; стоимость единицы и частота ограничены.

## Удаление finalizer, purge и восстановление

Finalizer принадлежит основному пакету FIC, а persistent fence — root-controlled
каталогу вне удаляемых package-owned деревьев. Release package-session держит
daemon.lock через все действия и финальные proofs; выставляет durable release
phase до исчезновения helper/units. Снятие delivery units не снимает fence.

* Пока пакет устанавливается/обновляется: helper/units должны быть восстановлены
  package manager; postinst оставляет InstalledButFenced, включает доставку.
* Успешное remove/purge: helper, timer/path/service исчезают; **автоматическая
  финализация отсутствующего пакета не требуется**. Fence остаётся tombstone,
  запрещающим старому cooperative бинарнику startup. Полный purge не удаляет этот
  security state; отсутствие fence не используется как proof успешного удаления.
* Failed erase/partial removal: fence сохраняется независимо от наличия helper.
  Если helper исчез, автоматическая доставка технически невозможна. Требуется
  reinstall/закрытый recovery после восстановления пакета. Нельзя обещать timer
  recovery при удалённом timer или исполнителе.
* Reinstall/abort-remove: восстановленный helper читает прежний fence, manifest,
  journal и masks; выполняет закрытый recovery с fresh proofs, не считает reinstall
  автоматическим разрешением. Окончательный installed proof остаётся отложенным.
* Раннее удаление helper в upgrade и старый timer, видящий новый бинарник, не дают
  authority: протокол/версия fence/manifest должны быть согласованы под lock;
  непонятное сочетание остаётся fenced.

Гарантии старых неблокирующихся бинарников ограничены согласованным deployment
contract: persistent masks managed units + проверенные process/cgroup identities;
независимый ручной запуск старой копии административно запрещён. Tombstone не
является kernel-level fencing произвольного privileged execution.

## Native acceptance и текущая доказательная база

`retry_protocol_probe.cpp` / `retry_lifecycle.py` используют scaled 250 ms admission,
300 ms timer, 700 ms timeout. Эти значения только ускоряют тесты, не заменяют
production limits. Проверяются: >=8 временных попыток без completion event,
hook storm/cooldown, structural block без дорогих повторов, crash и timeout с
последующим timer recovery, manager reexec, сохранение tombstone после удаления
units. Фактические результаты находятся в `evidence/retry-lifecycle-*.log`.

Фикстура **не читает MutationJournal/PAM/incident/реальный manifest и не запускает
FIC**. Она не доказывает closed structural recovery, безопасность package-session,
настоящий purge/reinstall, kernel reboot/power loss или production budget enforcement.
Эти gates остаются обязательными при реализации M1. Ранее полученные настоящие
DEB/RPM phase/lock reproductions остаются отдельными evidence, не заменяют эти gates.
