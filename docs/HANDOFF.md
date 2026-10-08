# FIC handoff

## Current base

* Branch `main`; current follow-up based on `3d39cd7ed7b1492870f64c99fc3786bff11ec9fb`.

## Current task

* Fresh verification and durable re-arm of `Discharged` Model A obligations — реализовано.

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
* `Discharged` is a past proof only. Each ISOLATE reconciliation freshly verifies it. A proven reactivated previously selected runtime or new qualifying login re-arms `Pending` durably before termination. Unproven identity/runtime or failed re-arm degrades without unsafe mutation. Periodic reconciliation is not continuous enforcement.

## Completed

* Follow-up: controller fencing-before-severity, active store proof, unified boot rebase, clear diagnostics; strict parser/schema 2 and state-bound conditional writes.
* Удалена shell-based классификация (`Service` по `nologin/false/true`); Model A в `classifyProductionContainmentIdentity`.
* Исполняемые RED R1–R5 на base; GREEN регрессии на crash/boot/missing store/parser/fsync, сохранены исходные R1–R8 Model A.
* Обновлены IncidentControllerTests/LogindSessionContainmentBackendTests под Model A.
* Follow-up: new login refreshes selection evidence and durably re-arms; discharged targets receive fresh runtime proof, with bulk conditional re-arm before user actions. RED D1–D6 executable on base `3d39cd7` and GREEN after implementation.

## Changed areas

* Current follow-up: `fic/src/incident/IncidentController.cpp`, `tests/fic/incident/ModelAContainmentTests.cpp`, `fic/README.md`, `docs/HANDOFF.md`.

## Validation

* RED-before: R1–R5 executable on `5a07798`, each failed on its intended assertion.
* Fresh Debian 12 Docker full build PASS. CTest as root excluding `mutation_journal_tests`: **142/142 PASS** (Git safe.directory set for read-only `/src`); the excluded journal executable separately passed under UID 1000. Initial unadjusted root CTest had 4 failures: Git safe.directory, root-dependent journal harness, and two device fixtures missing the new target-store test ownership override; all affected cases were rerun successfully.
* Targeted Model A/controller/backend/recovery tests PASS. Final targeted Model A/controller builds and direct runs PASS on Debian 13, Ubuntu 24.04, ALT p11. ALT image lacks `ctest`; Ubuntu 26.04 configure is blocked by missing PAM development files in the image.
* `git diff --check` PASS before commit.
* Current follow-up: executable RED D1–D6 each failed on base `3d39cd7` for the intended assertion; GREEN Model A/controller/backend/recovery tests passed. Fresh Debian 12 full build PASS; CTest **142/142 PASS** with `mutation_journal_tests` excluded from root run and separately **PASS under UID 1000**. The first build attempt stopped at 90% only because `/tmp` filled; after removing the previous follow-up's temporary build and resuming with `-j2`, it passed.
* Final targeted Debian 13, Ubuntu 24.04 and ALT p11 Model A/controller runs PASS after extra crash tests. Ubuntu 26.04 configure is blocked by PAM development files missing from the local image.

## Remaining

* Real systemd-logind/desktop E2E requires disposable staging; fake transport does not prove desktop lock behavior. Identity recheck and D-Bus termination retain the documented narrow race. Network quarantine remains `NullIncidentNetworkBackend`.
