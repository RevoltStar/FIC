# FIC handoff

## Current base

* Branch `main`; task base `0de37d3319fd22f07cbeddfc628a9b7ba1e7a807`.

## Current task

Device Control → Incident Response integration. Выполнено.

## Device Control → IncidentController (detect-only boundary)

* **Прежняя production regression устранена:** `fic-dick` отправлял устаревшую
  команду `command="lock"`, которую основной daemon больше не поддерживает.
  Теперь используется `incident_device_missing`.
* **Detector event (fic-dick → fic):** `{command, device_ids[], device_ids_total}`.
  Только ФАКТ нарушения; severity/mode/containment авторитетно НЕ передаются.
  Список ограничен (64 id), truncation сохраняет общий total. Пустой список,
  неизвестные поля, нецелые id и неверная schema отклоняются.
* **Авторизация:** peer должен быть root-UID system device daemon
  (`SO_PEERCRED`); членства в административной группе недостаточно. Source
  устанавливает main daemon (`IncidentSource.name="device"`), поле `source`
  из JSON не читается.
* **Настройка:** `DC/DeviceControl/permanent_device_missing_severity`, токен
  NONE/SOFT/STANDARD/HARD/ISOLATE, заводской default STANDARD, status ENABLE.
  Это НЕ `Policy::violation_severity`: реакция на runtime-факт отсутствия
  устройства, а не на apply failure. У самой policy `violation_severity=NONE`,
  чтобы её собственная ошибка применения не породила самостоятельный incident.
  **Недоказуемая настройка — fail-closed ISOLATE:** резолвер
  (`fic::daemon::resolve_device_missing_severity`, `fic/src/daemon/
  DeviceIncidentEvent.{h,cpp}`) различает доказанный DISABLE и доказанный
  NONE (намеренное игнорирование) от UNPROVEN (политика отсутствует, статус
  не ENABLE/DISABLE, значение отсутствует или не распознано): UNPROVEN даёт
  fail-closed реакцию ISOLATE через `IncidentController.raise()`, а не
  молчаливое подавление инцидента.
* **Режимы:** OFF — не изменяет lockstatus, не создаёт incident audit/
  notification; PASSIVE — persistent severity + audit + notification, без
  containment; ACTIVE — плюс существующий containment. NONE/DISABLE —
  escalated=false, `ok=true` с `ignored=true` (отличимо от ошибки IPC).
* **Монотонность:** повторное событие того же/меньшего уровня не повышает
  severity и не повторяет notification; reconnected device НЕ вызывает
  automatic clear; после административного clear продолжающееся нарушение может
  снова повысить severity.
* **Retry:** при недоступности main daemon fic-dick запоминает
  `retry_required` и периодически (5s, без busy-loop) перечитывает нарушения из
  авторитетной БД и повторяет доставку; restart device daemon восстанавливает
  проверку через startup reconciliation. State в памяти, без persistent queue.
  Retry-обязательство **глобальное** и очищается только полной проверкой с
  **доказанно успешным** чтением inventory (`DB::getAllDevicesChecked()`:
  prepare OK, step до `SQLITE_DONE`, finalize OK): ошибка prepare/step/init БД
  означает недоказанный inventory — «all connected» не объявляется, retry
  сохраняется (`updatePermanentIncidentRetry()` в
  `daemon/PermanentDeviceRetry.h` — единая production-функция перехода).
  Пустая частичная проверка или успешная доставка частичного batch retry не
  меняет. Ошибка чтения БД не позволяет объявить «all connected».
* **Acknowledgement vs containment:** единая ACK-матрица sender/receiver
  (`make_device_incident_ack_response` ↔ `parse_device_incident_acknowledgement`,
  контракт закреплён `device_incident_response_compat_tests`):
  DISABLE/NONE/OFF → `acknowledged=true, persistence_confirmed=false,
  ignored=true` (не ошибка — обязательства записи нет); PASSIVE/ACTIVE с
  durable severity → `acknowledged=persistence_confirmed=true, ignored=false`;
  persistence failure → оба false, delivery не закрыт.
  `IncidentResult.persistenceConfirmed` отражает фактический результат
  `IncidentStateStore::raiseToAtLeast()` (durable запись), независимо от
  containment-результата. `acknowledged=true` НЕ доказывает containment:
  `DEGRADED`-containment при подтверждённой персистенции даёт
  `incident_ok=false`, сообщение `device incident recorded; containment
  degraded` и не запускает повторную доставку — за containment отвечает сам
  IncidentController. Парсер никогда не ремонтирует несогласованный ответ
  (не превращает `acknowledged=false` в `true`).
* **Deadlock:** `device_regenerate_policy` handler fic-dick НЕ вызывает
  `check_permanent_devices`, поэтому цепочка fic→fic-dick→fic не существует.
* **Ответ:** `ok=true` = событие обработано, НЕ «компьютер заблокирован»;
  PASSIVE сохраняет severity без containment; malformed/unknown response —
  delivery failure.



* Close the administrative IPC ACTIVE preflight bypass through module aliases.

## Accepted architecture / invariants

* `canonical_module_name(policyRegistry, module)` defines module identity for policy mutation. After request parsing and schema validation, preflight and mutation must see the same canonical module. Policy names and values stay case-sensitive.
* Managed ACTIVE transitions block declared SSH entry points before configuration write. OFF/PASSIVE behavior, readiness proof, journal and rollback remain unchanged.

## Completed

* Canonicalized the validated IPC request module before ACTIVE preflight and `handle_request`.
* Added alias cases to the guarded transition test and a production source ordering check. The ordering check failed on the task base before the fix.

## Changed areas

* `fic/src/main.cpp`, `fic/src/incident/IncidentModeTransition.h`, `tests/fic/incident/IncidentModeTransitionTests.cpp`, `tests/fic/modules/net/ssh/static_checks.py`.

## Validation

* RED before fix: `python3 tests/fic/modules/net/ssh/static_checks.py /home/admsys/FIC` failed: `IPC must canonicalize module before ACTIVE preflight`.
* GREEN after fix: same check passed; `git diff --check` passed.
* Fresh Debian 12 container configure and targeted `fic` / `incident_mode_transition_tests` build passed; targeted test passed.
* Full container build passed; CTest passed 133/133 (excluding `mutation_journal_tests`).
* `mutation_journal_tests` passed by direct binary execution as UID 1000. A CTest attempt with read-only `/build` could not create `LastTest.log`, so it was rerun directly.

## Remaining

* No live host SSH/PAM or policy mutation was performed.
