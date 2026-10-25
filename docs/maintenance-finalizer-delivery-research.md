> Historical M1 design/research, superseded by [package-lifecycle.md](package-lifecycle.md).
> Runtime/finalizer/coordinator/legacy compatibility guarantees below are not the current production contract.

# M1: исследование доставки deferred finalizer

## Scope и статус

Исследование по отдельному запросу: сравнение архитектур и native reproductions,
**не реализация finalizer/M1**. Новый watcher, production units, package hooks,
снятие fence и запуск daemon здесь не добавлялись. Существующий M1 draft остаётся
отдельной незавершённой работой. Fixture C++ oneshot не является security verifier.

Принятый контракт: postinst оставляет InstalledButFenced. Только закрытый finalizer
после свежих package/journal/PAM/incident proofs под daemon.lock завершает durable
lifecycle, освобождает lock и затем разрешает штатный startup. Событие — повод
повторить proof, никогда не authority. Half-configured, ambiguous rpmdb, занятые
package-manager locks, неизвестные версии, corrupt fence и неполный release сохраняют
fence. Неудача доставки ухудшает availability, но не разрешает startup.

## Native evidence

Все операции выполнены в disposable containers без host `/etc`, `/run`, cgroup
или Docker socket mounts. systemd — настоящий PID1 в private cgroup/mount namespace.
Синхронизация сценариев — FIFO/select, не sleep. Bounded boot readiness использует
отдельный инфраструктурный timeout. Общий kernel — WSL2: это пять userspaces, не пять
kernel/VM или power-loss проверок.

| Userspace | systemd / dpkg | dpkg failed/configure-a/apt + hooks | path events/replace/reexec/rearm |
|---|---|---|---|
| Debian 12 | 252 / 1.21.23 | PASS | PASS reproductions |
| Debian 13 | 257 / 1.22.22 | PASS | PASS reproductions |
| Ubuntu 24.04 | 255 / 1.22.6 | PASS | PASS reproductions |
| Ubuntu 26.04 | 259 / 1.23.7 | PASS | PASS reproductions |
| ALT p11 | 258 / RPM 4.13.0.1 | Native RPM/filetrigger PASS | PASS reproductions |

PASS reproductions означает, что **ожидаемый дефект воспроизведён**, а не что
механизм доставки надёжен. Полные outputs и fixtures:
`tests/integration/maintenance-finalizer-research/{README.md,evidence/}`.

### DEB: фактический порядок и hooks

На всех четырёх DEB userspaces:

1. Настоящий `postinst configure` видит
   `install ok half-configured`, включая успешный повтор `dpkg --configure -a`.
2. Dummy trigger (`interest-noawait`, реальный `dpkg-trigger`) тоже выполняет
   `postinst triggered` при half-configured status. Trigger не final installed proof.
3. Failed postinst оставляет half-configured. После configure-a статус installed.
4. Прямой dpkg `--post-invoke`: после успешного действия installed, dpkg и frontend
   record locks свободны. Но после failed postinst тот же hook видит half-configured;
   сам факт вызова post-invoke не доказывает успех.
5. apt `DPkg::Post-Invoke`: installed уже виден, dpkg lock свободен, **frontend lock
   ещё занят**. Синхронный finalizer, ожидающий выхода родительского apt, создаст
   deadlock. Hook должен только асинхронно запросить независимый oneshot.

Использованы настоящие dummy DEB installation, injected failed postinst, configure-a,
apt reinstall, dpkg trigger/post-invoke и apt post-invoke. Не устанавливался пакет FIC.
Это согласуется с [Debian Policy maintainer-script lifecycle](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)
и [dpkg triggers](https://sources.debian.org/src/dpkg/1.17.25/doc/triggers.txt/);
вывод о конкретных locks основан на native fcntl contention, не на документации.

### ALT RPM

В `%post` новая версия уже присутствует в rpmdb; transaction record lock
`/var/lib/rpm/.rpm.lock` удерживается. В поддерживаемом ALT `/usr/lib/rpm/*.filetrigger`
после successful install lock **также удерживается**. После выхода rpm он свободен.
Поэтому rpmdb entry и filetrigger invocation не означают завершение transaction.

При injected failed `%post` upgrade rpm вернул exit 1 и оставил **две версии**
fixture в rpmdb. Query success/наличие ожидаемой новой версии недостаточны: finalizer
обязан проверять уникальность и согласованность всего поддерживаемого набора FIC,
manifest и lifecycle proofs. В этом неуспешном прогоне наш filetrigger не исполнился,
несмотря на строку запуска posttrans-filetriggers: нельзя полагаться на доставку hook
при failure. Не обобщать это наблюдение на каждый возможный RPM failure.

Исходный fixture с upstream `%posttrans` был отвергнут именно этим ALT builder
(`Macro %posttrans not found`); он сохранён как compatibility finding, не обход.
Реальный ALT механизм исследован отдельно. Upstream описание
[RPM scriptlets](https://rpm.org/docs/latest/manual/file_triggers.html) не заменяет
проверку старого ALT backend. Изначально отсутствовавшие rpm-build/Python установлены
только в временный container; rpmbuild выполнен от отдельного непривилегированного
builder согласно ALT policy.

### systemd.path + oneshot

На всех пяти userspaces одинаково:

* Первое close-write событие вызывает service.
* Пока service заблокирован на FIFO, второе close-write приходит. После завершения
  service **нет второго запуска** в bounded observation window. Наивная доставка
  finalizer теряет wakeup, если он проверил package state до его изменения.
* Atomic rename replacement наблюдаемого файла вызывает следующий запуск. Это
  положительный частный тест; не доказательство отсутствия всех inode/watch races.
* `systemctl daemon-reexec` сохраняет способность наблюдать последующее событие.
* Изменение при остановленной `.path` + повторный start `.path` **не делает rescan**.
  Значит самостоятельный boot/restart attempt необходим.

[systemd.path](https://www.freedesktop.org/software/systemd/man/258/systemd.path.html)
определяет PathChanged по закрытию writable file; это полезный сигнал и для lock
files, но не обещание одного service invocation на каждое событие. Наблюдение
atomic replace/manager reexec не устраняет native active-service lost-wakeup.
Не измерялось точное число kernel inotify coalescences: проверена потеря dispatch,
а не независимый kernel-level event counter или искусственное queue overflow.

### Дополнительные native transport проверки

На ALT с реальным systemd и фиксированным **C++** fixture oneshot:

* half-configured fixture state → defer, без accepted marker;
* затем installed fixture state, без нового path event → отдельный одноразовый
  timer доставляет следующую попытку, marker появляется;
* SIGKILL FIFO-blocked service → bounded `Restart=on-failure` доставляет повтор;
* boot-enabled fixture oneshot запускается после restart самого private PID1
  container, persistent `/var/lib` fixture сохраняется.

Это проверка dispatch, не доказательство FIC proofs, durable fence recovery или
настоящего reboot ядра. Production finalizer и его полные proofs этим probe не реализованы. На Debian12
native C++ pidfd probe подтвердил bounded kernel notification о выходе pinned child
без sleep/polling loop; интеграция с реальным apt/RPM owner PID пока **не проверена**.

## Сравнение архитектур

| Модель | Safety при строгом finalizer | Liveness | Сложность / сопровождение |
|---|---|---|---|
| Только `.path + oneshot` | Fence можно сохранить | Недостаточна: потеря wakeup при active service; нет boot rescan | Малая, одинаковые базовые units, но непригодна как единственный transport |
| Только package hooks/triggers | Hook не authority; proofs обязательны | Не покрывает failures/crash/watch loss; dpkg trigger слишком ранний, ALT trigger под transaction lock | Разные DEB/RPM механизмы; apt-only hook не покрывает прямой dpkg |
| `.path + boot + hooks + rate/cost-bounded timer recovery` | Сильная при неизменных guards/proofs | Повторяемая при временном ожидании без общего лимита попыток; требует исправной доставки | Умеренная, нет нового постоянного процесса; требуется durable cooldown и отдельный structural block |
| Собственный event-driven watcher | Те же proofs; больший привилегированный surface если root | При fair scheduling, стабильном FS и supervision: watch-before-check, queued events, overflow/restart rescan устраняют изученные lost-wakeup классы | Новый компонент, native tests/rearm/overflow/upgrade/least privilege; не реализован и пока не согласован |

Ни одна модель не доказывает safety против root writer, обходящего protocol.
Произвольные административные остановки/masks finalizer, потеря FS, бесконечные crashes
или отсутствие systemd исключают безусловную liveness. В таком случае fence остаётся.

## Рекомендация без нового постоянного процесса

Для следующего согласованного implementation этапа рекомендую hybrid:

1. Закрытый C++ oneshot с фиксированными proofs, действующий независимо от caller.
2. Явная boot активация и initial rescan; не ожидать этого от PathChanged.
3. Signals от package DB и lifecycle directory + DEB dpkg post-invoke/apt hook и
   native ALT filetrigger. Все hooks только `start --no-block` фиксированной unit;
   не ждать parent manager синхронно и не принимать environment как authority.
4. При early invocation читать настоящие record-lock owners; при необходимости
   исследовать bounded pidfd wait **вне daemon.lock**, затем повторить все proofs
   под lock. Сначала проверить PID identity/reuse races и совместимость на матрице;
   prototype пока подтвердил только kernel primitive.
5. Повторяемый timer без общего лимита попыток для временного ожидания;
   durable rate/cost gate и отдельный structural block. Точный контракт, включая
   удаление helper и tombstone: [retry/recovery lifecycle](maintenance-finalizer-retry-lifecycle.md).
6. Crash/timeout не исчерпывают последующие timer attempts. Fence сохраняется при
   любом недоказанном условии; fixture exit 0 не означает FIC SUCCESS.
7. После proof — durable lifecycle completion, unlock, затем штатный daemon start.
   Concurrent startup во время pending/failed proofs всё ещё запрещён fence.

Первоначальная рекомендация конечного общего retry budget отклонена: она не
обеспечивала automatic delivery после произвольно долгой transaction. Новый
контракт ограничивает частоту/стоимость попыток, сохраняя повторяемый recovery.
Собственный постоянный watcher не требуется и не реализуется.

## Что ещё не проверено

* Настоящий power loss/reboot kernel, queue overflow/watch-root deletion, настоящие длительные
  package transactions и production persistent rate/cost protocol.
* Native FIC finalizer/package-session/fence recovery и manifest proofs (их ещё нет).
* apt/RPM pidfd-owner handoff, настоящее удаление/abort/reinstall FIC.
* Исходный boot/crash probe — ALT; новая retry-protocol matrix описана в retry lifecycle и evidence.

Полную project build/CTest не запускали для этого исследовательского этапа:
production code не менялся, запускались standalone fixtures. `git diff --check` PASS.
Никакого production watcher/finalizer или утверждения о завершении M1.
