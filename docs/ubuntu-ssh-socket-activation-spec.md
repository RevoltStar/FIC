# Ubuntu SSH socket activation — verified end-to-end integration

## Статус и цель

Отдельное будущее ТЗ для Ubuntu 24.04/26.04. Сейчас их production SSH policy path
возвращает Unsupported без Debian/legacy fallback. Этот документ не включает
реализацию Ubuntu в завершение Debian-этапа.

Цель: пять SSH-политик возвращают SUCCESS только при доказанных supported inputs,
selected-policy semantics и соответствующем фактическом service/socket runtime.
Особенно `ssh_port`: одного `sshd -T` или нового service PID недостаточно, если
listener принадлежит `ssh.socket` и передаётся службе через socket activation.

База для переиспользования — Debian `Ssh::apply`, reference builder, shared resource
mutex/Prepared gate, CAS/durability receipts, bounded runtime receipt, SSH adapter
и существующий generic engine. Не копировать их в отдельный restart engine.

## 1. Native аудит до проектирования

На обеих Ubuntu в disposable systemd PID1 контейнерах зафиксировать реальные
package versions, units/aliases, argv/environment, Type/NotifyAccess, socket
properties, triggers/dependencies и generator inputs/outputs. Не предполагать,
что Ubuntu 26.04 повторяет Ubuntu 24.04 или что stock units идентичны Debian.

Проверить:

* Кто создаёт listener, кто владеет socket FD, кому он передаётся.
* Фактические IPv4/IPv6 addresses/ports и соответствие listening inodes процессу,
  socket unit и новой service invocation.
* Native генерацию настроек порта, момент её применения и daemon-reload semantics.
* Service inactive при socket active, pending activation, restart и failed states.
* Namespaces, usr-merge, HostKeys, EnvironmentFile, Include/Match и private publication
  boundaries; не расширять configuration authority автоматически.
* Side effects и порядок безопасной смены порта без потери ownership/provenance.

Событие активации или значение unit property — сигнал/наблюдение, не самостоятельное
доказательство чтения проверенных inputs либо фактического listener.

## 2. Архитектура — отдельное согласование

После аудита определить supported service/socket state matrix и typed immutable
launch contract. Явно решить, можно ли и как подтверждать запуск из состояния
socket-active/service-inactive, не превращая apply в скрытый enable/start/repair.
Disabled/masked/неизвестные конфигурации отклонять до мутаций.

Определить native способ конфигурирования Port: generator либо ownership-safe
managed override только если это подтверждено исследованием и согласовано.
Не переписывать чужой socket unit/drop-in и не трактовать его hash как ownership.
Если необходимы новые ownership payload/schema или расширение generic engine,
сначала представить design и согласовать границу; не встраивать обход в SSH adapter.

Запретить SUCCESS при прежнем открытом listener, лишнем порте, чужом socket FD,
неподтверждённой service invocation или socket activation вне supported contract.
Не обещать атомарность against arbitrary privileged writers; описать реальные
контрольные точки и остаточные гонки.

## 3. Transaction и recovery

* Единая сериализация SSH config/service/socket resource, существующий daemon
  admission contract; package/M1/fence не обходить и не переделывать.
* До save — native support/enablement/runtime preflight, exact Include negative
  manifest, desired values отдельно от foreign references и journal ownership.
* После save — installed-state identity, verified RO inputs, native semantics,
  socket/service activation и listener proof, cleanup, persistent proof, commit.
* Ошибка после effect/unknown сохраняет provenance и отдельно сообщает saved,
  activated, listener-confirmed, cleanup и committed outcomes.
* Не восстанавливать исторические файлы без ownership/CAS; unresolved Prepared
  не разрешать повторным apply/disable. Не добавлять force/adoption.
* In-memory no-op receipt расширить только доказанными socket/listener identities
  и launch inputs. No-op не должен вызывать лишний restart socket/service.
* Учитывать реальные start limits обоих units; не reset-failed/enable/unmask их.

## 4. Native acceptance gates

Ubuntu 24.04 и 26.04: настоящие stock package/unit/sshd/systemd, network none,
loopback probes, без host mounts/SSH/PAM. Проверять реальные policy classes,
MutationJournal и kernel listeners, а не только component transport PASS.

Обязательны:

1. Fresh apply, foreign compliant unowned и устойчивый no-op всех пяти политик.
2. Смена Port с proof нового listener и отсутствия старого/лишнего listener.
3. Socket-active/service-inactive и все утверждённые enabled/runtime состояния.
4. IPv4/IPv6, inherited FD, aliases, approved generator/override paths.
5. External/conditional Includes, symlink/recursion/manifest bounds, selected Match,
   foreign Port, orphan/drifted ownership, unresolved Prepared.
6. Unsupported socket/launch overrides и отказ без изменения config/journal/runtime.
7. Deterministic races unit/drop-in/generator/enablement/service/socket/FD/listener;
   чужой restart, STOP после READY, изменения до final proof.
8. CAS, unknown writer, durability, activation/listener failure, CleanupFailed,
   persistent drift и journal commit failure; truthful provenance, без blind restore.
9. Regression Debian12/13 module/adapter gates, generic activator на поддерживаемой
   матрице, SSH provenance/rollback/MutationJournal, affected/full CTest и diffcheck.

Полный daemon/package/PAM login и cross-kernel/VM validation обозначать отдельно.
Документировать поддержанные сценарии и конкретные ограничения. Не объявлять
Ubuntu поддержку по одной успешной активации service при непроверенном socket.
