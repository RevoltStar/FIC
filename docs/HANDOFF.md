# FIC handoff

## Current base

* Branch `main`; follow-up applied on `5a07798aeff71cfa9ae4618c26229bb7598370a5`.

## Current task

* Crash-consistent lifecycle для Session Containment Model A — реализован.

## Accepted architecture / invariants

* **Model A:** цели containment выбираются только по доказанным обычным logind login-сессиям (`Class=user/user-early/user-light/user-early-light` + NSS identity proof + не root/recovery). Login shell, UID-диапазоны, имя пользователя и `/etc/passwd` НЕ участвуют в выборе цели. `Service` больше не производится классификатором.
* `IncidentController` owns severity/mode decisions; `LogindSessionContainmentBackend` only inventories, acts, and verifies. OFF/PASSIVE do not mutate sessions. Network quarantine remains the existing null backend.
* **Durable target store** `incident_session_targets` (рядом с lockstatus, root-owned 0640, atomic replace + fsync файла и каталога, версионированный JSON: `boot_id`, `incident_generation`, targets с evidence). Инвариант: **сначала durable регистрация цели, затем разрушающее действие**; неуспешная регистрация удерживает `TerminateSession` и даёт `DEGRADED`.
* Списки целей: session-level — обычные login-сессии текущего инцидента; user-runtime (ISOLATE) — **только** pending-цели из store. `ListUsers` — не источник новых целей, только механизм действия/верификации выбранных UID через `lookupProvenUser(uid, expectedName)`.
* Переживает: повторный `reconcile()`, частичный отказ `TerminateSession`/`TerminateUser`, рестарт FIC (store), эскалацию STANDARD→HARD→ISOLATE. Проверенный kernel reboot (смена `boot_id`) разрешает runtime-обязательства предыдущей загрузки; soft-reboot с тем же `boot_id` их сохраняет.
* При первом raise из proven `UNLOCKED` пустое новое поколение schema 2 с lifecycle marker durable фиксируется **до** записи ненулевой severity, включая SOFT/PASSIVE. Два persistent-объекта не атомарная транзакция: авария до severity оставляет `UNLOCKED`, после severity — доказанное новое поколение. Failed fencing пытается durable BROKEN_STATE и запрещает session/user mutations.
* При durable `UNLOCKED` clear затем очищает store; ошибка cleanup видна в ответе, а следующий инцидент снова фиксирует пустое поколение. Active severity + отсутствующий/повреждённый/старой схемы store → `DEGRADED` без session/user mutations.
* Проверенная смена kernel boot ID durably rebases store на пустые targets при любой active severity до обработки новых сессий. Restart FIC/logind с прежним boot ID не rebases; недоказанный boot ID degrades.
* Недоказуемый (повреждённый) store → `DEGRADED`, никаких unsafe-действий и никогда не пустой успех. UID reuse (UID теперь другой аккаунт) → отказ + `DEGRADED`.
* Root, configured recovery-group members, greeter/service и unproven identities никогда не являются целями. Unknown class делает inventory недоказанным.
* Logind actions are pinned to its unique D-Bus owner, with immediate identity recheck. The narrow race between recheck and terminate was accepted for explicit documentation.

## Completed

* Follow-up: controller fencing-before-severity, active store proof, unified boot rebase, clear diagnostics; strict parser/schema 2 and state-bound conditional writes.
* Удалена shell-based классификация (`Service` по `nologin/false/true`); Model A в `classifyProductionContainmentIdentity`.
* Исполняемые RED R1–R5 на base; GREEN регрессии на crash/boot/missing store/parser/fsync, сохранены исходные R1–R8 Model A.
* Обновлены IncidentControllerTests/LogindSessionContainmentBackendTests под Model A.

## Changed areas

* `fic/src/incident/{IncidentController,IncidentSessionTargetStore}.{h,cpp}`, incident/controller and two device-incident fixture tests, `fic/README.md`, `docs/HANDOFF.md`.

## Validation

* RED-before: R1–R5 executable on `5a07798`, each failed on its intended assertion.
* Fresh Debian 12 Docker full build PASS. CTest as root excluding `mutation_journal_tests`: **142/142 PASS** (Git safe.directory set for read-only `/src`); the excluded journal executable separately passed under UID 1000. Initial unadjusted root CTest had 4 failures: Git safe.directory, root-dependent journal harness, and two device fixtures missing the new target-store test ownership override; all affected cases were rerun successfully.
* Targeted Model A/controller/backend/recovery tests PASS. Final targeted Model A/controller builds and direct runs PASS on Debian 13, Ubuntu 24.04, ALT p11. ALT image lacks `ctest`; Ubuntu 26.04 configure is blocked by missing PAM development files in the image.
* `git diff --check` PASS before commit.

## Remaining

* Real systemd-logind/desktop E2E requires disposable staging; fake transport does not prove desktop lock behavior. Identity recheck and D-Bus termination retain the documented narrow race. Network quarantine remains `NullIncidentNetworkBackend`.
