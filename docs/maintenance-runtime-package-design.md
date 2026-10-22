# M1-C: предварительный runtime — пакетный contract

## Статус

Выделение runtime одобрено пользователем. Это проект пакетной архитектуры и native
RED reproductions, **не реализация безопасного FIC package lifecycle**. Двухстадийный runtime retention принят: преждевременный совместный erase/autoremove
явно отказывает, сохраняя runtime до proof из предыдущей завершённой transaction. Production packaging ещё не изменён; никаких fallback на legacy binary.

## Схема ownership и зависимости

| Пакет | Ownership / роль | Зависимость |
|---|---|---|
| `fic-runtime` | Единственный ELF текущего `fic` engine; закрытые lifecycle-команды, finalizer service/path/timer, boot delivery, hooks | Только системные runtime libraries; ни одной зависимости от FIC-пакетов |
| `fic` | Policy resources/configs/PAM integration/daemon units; обычный private entrypoint ссылается на runtime ELF | DEB `Pre-Depends: fic-runtime (= full package version)`; RPM exact runtime EVR + prerequisite ordering и lifecycle ABI |
| Остальные FIC-пакеты с mutating scripts | Существующие собственные resources; fixed lifecycle actions через тот же runtime до security mutations | Ранний runtime prerequisite; не создавать обратных зависимостей runtime |

Не создавать второго executable с копией policy/ownership checks. Существующий
`fic` build target остаётся единственной реализацией. Меняется packaging ownership
его установленного ELF. Никакого trusted FD/env handoff: fixed command получает
тот же guard; fence закрывает промежутки между package stages, package-session
удерживает guard непрерывно через DM/DE/PAM/hooks/proofs.

**ELF установить по новому private path** (кандидат `/usr/libexec/fic/fic-runtime`);
`/opt/fic/bin/fic` в основном пакете становится ссылкой на него. Это избегает
cross-package collision с ELF, которым владеет legacy `fic`, особенно на RPM, где
нельзя считать DEB Replaces переносимым решением. Public command/daemon semantics
сохраняются. Pre-scripts вызывают именно заранее установленный runtime, не старый
private/public entrypoint. CMake/staging/native file-type transition ещё нужно
реализовать и проверить. Нельзя внедрить `--replacefiles`/force fallback.

Runtime executable — root-owned, без setuid и group/other write. Fresh runtime не
должен требовать существующей группы fic для выполнения root bootstrap. Разрешения
и manifest должны совпадать после настройки; unprivileged mutation остаётся
запрещённой guard/root checks. Системные зависимости вычисляются по ELF, внутренние
fic-core/policy/ipc остаются статически слинкованными; runtime не зависит от `fic`
или `fic-dick`. Все прямые/косвенные package edges проверить на отсутствие циклов.

## Version/ABI и ordering

* Новый main pre-script принимает только настроенный runtime ожидаемой полной
  package version (включая release/epoch, где применимо) и ожидаемого lifecycle ABI.
  Installed-but-unconfigured или случайный старый runtime не даёт authority.
* Finalizer сверяет согласованность версий main/runtime/обязательных FIC-пакетов,
  immutable manifest, реальный installed state и весь lifecycle proof; dependency
  resolver не заменяет эти проверки. Не использовать только имя ELF/`--version`.
* Transitional old-package scripts могут выполняться уже с новым runtime: native
  upgrade/downgrade подтвердил это. Для них требуется явно поддерживаемый ABI,
  separate от final exact-version proof. Не объявлять произвольную старую версию
  совместимой. Unknown ABI/schema или неподдержанный downgrade — отказ до mutations.
* DEB native `Pre-Depends (= version)` на fixtures обеспечивает новый runtime до
  main preinst при apt install/upgrade/downgrade; missing/mismatch отвергается до
  main preinst. Реальные версии FIC и manifests ещё не проверены.
* ALT fixture: `Requires(pre): runtime = version`, installed exact dependency и
  `Requires(preun,postun): lifecycle-abi = 1`; runtime Provides ABI. Native RPM
  упорядочил fresh/upgrade/downgrade и erase. Это не доказательство всех возможных
  transaction graphs; actual FIC packages и legacy transition требуют своих gates.

## Legacy bootstrap и crash boundaries

1. Runtime payload ставится в новом месте и ещё не меняет policy resources. Его
   собственный initial pre-script не выполняет FIC group/chown/stop/attach actions,
   которые потребовали бы ещё отсутствующего coordinator.
2. После доступности нового ELF закрытый runtime bootstrap создаёт durable fence,
   сохраняет mask provenance, persistently fences managed legacy units, останавливает
   и доказывает unit/cgroup/process identities. Не полагаться на свободный daemon.lock.
3. Новый main pre-script повторно получает admission и проверяет fence/compatibility.
   Только затем выполняются предусмотренные group/stop/security actions до unpack.
4. Main postinst конфигурирует инфраструктуру под тем же contract и оставляет
   InstalledButFenced. Runtime уже владеет delivery units и остаётся доступным при
   failed main configure/abort. Finalizer не запускает package-manager repair.
5. Crash до runtime bootstrap не сопровождается release: legacy-owned resources
   должны оставаться нетронутыми. Crash после bootstrap оставляет fence/маски через
   reboot. Между runtime installation и main unpack не должно быть автоматической
   legacy reactivation после начала release. Это пока acceptance, не доказанный gate.

Административный запрет независимого запуска старых копий остаётся обязательной
предпосылкой; managed masks не защищают от произвольного privileged writer.

## Lifetime удаления и обнаруженный RED

**DEB Pre-Depends не удерживает runtime через main purge.** На Debian12/13 и
Ubuntu24.04/26.04 настоящий `apt purge main runtime` дал:

```text
main postrm remove helper=1
runtime prerm remove helper=1
runtime postrm remove helper=absent
runtime postrm purge helper=absent
main postrm purge helper=absent
```

ALT RPM с prerequisite ABI сохранил helper в `main %postun`, но собственный
`runtime %postun` выполнялся уже без helper. Кроме того, package transaction lock
ещё удерживается до выхода родительского manager (ранее native подтверждено).
Ни `postrm`, ни `%postun` собственного runtime не могут запустить удалённый ELF.
Нельзя ждать завершения родительской transaction в его script.

### Принятый двухстадийный retention contract

* Обычный remove/purge FIC сохраняет runtime установленным. Main release completion
  означает лишь завершение security release; это **не proof удаления пакета**.
* Runtime finalizer после окончания transaction под package-manager locks +
  daemon.lock подтверждает удаление/purge main и journal/PAM/incident state и
  durably переводит lifecycle в RemovedTombstone. ReleaseComplete остаётся pending
  для этой проверки. Tombstone находится вне package-owned/deleted directories.
* Runtime prerm/%preun запрещает собственный erase, пока нет этого proof из уже
  завершившейся предыдущей transaction. Он повторно проверяет текущее состояние,
  не доверяет одному старому marker. Никаких mutations при недоказанном eligibility.
* Поэтому совместное удаление main+runtime или autoremove может получить явный
  отказ с сохранённым runtime. Пакетный менеджер не объявляется восстановленным;
  его failure видим пользователю. После main purge и успешного deferred finalizer
  отдельная transaction может удалить runtime.
* До собственного payload removal runtime завершает все критические операции под
  admission и сохраняет tombstone. Его postrm/%postun не требуют уже удалённого ELF
  и не снимают fence. Purge runtime не удаляет tombstone и каталог его provenance.
* Reinstall восстанавливает единственный engine/delivery, но не обходит старый
  fence. Новый install/recovery делает fresh proofs; повреждённое состояние не
  присваивается автоматически. Неподдерживаемый ABI остаётся fenced.

Native **retention prototype**, не FIC verifier: runtime pre-removal refused при
отсутствии model proof; helper остался доступен в main purge/erase; после возврата
manager harness обозначил model proof и следующая transaction удалила runtime.
Механизм lifetime работоспособен на fixtures. Реальный eligibility/controller,
crash/reboot, failed erase/reinstall и package abort proofs ещё не реализованы.

Если требуется успешное удаление обоих пакетов в одной transaction с post-transaction
proof, принятый lifetime недостаточен: нужен исполнитель, переживающий удаление
runtime. Такой bootstrap/copy/keeper механизм здесь не вводится автоматически.

## Native evidence / воспроизведение

`tests/integration/maintenance-finalizer-research/`:

* `pre_payload_probe.py deb/rpm`: новый helper отсутствует в initial pre-script;
  upgrade pre-script видит старый; новый доступен после unpack. Логи
  `evidence/pre-payload-{debian12,alt}.log`.
* `runtime_order_deb.py`: apt/dpkg fresh, exact mismatch refusal, upgrade,
  downgrade, failed configure/`--configure -a`, aborted remove, joint purge RED.
  `--retention-gate` — отдельный lifetime prototype. Логи
  `evidence/runtime-{order,retention}-{debian12,debian13,ubuntu2404,ubuntu2604}.log`.
* `runtime_order_rpm.py`: настоящий ALT rpmbuild/RPM, prerequisite order,
  fresh/upgrade/downgrade/mismatch/failed erase; `--retention-gate` prototype.
  `evidence/runtime-{order,retention}-alt.log`.

Только disposable containers; ALT rpmbuild непривилегированный builder. No host
security/package mutations. Это dummy packages, **не actual FIC native PASS**.
Actual legacy ELF→link upgrade, real FIC install/release/recovery, corrupted proofs,
crash/reboot между пакетами и окончательная матрица остаются обязательными.
